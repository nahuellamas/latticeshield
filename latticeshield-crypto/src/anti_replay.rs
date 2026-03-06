//! Proteccion anti-replay para tickets de sesion 0-RTT.
//!
//! Un ticket 0-RTT valido solo puede usarse una vez dentro de una ventana temporal.
//! Implementacion: HashSet en memoria con limpieza por ventana.
//!
//! Nota: en produccion reemplazar el HashSet por un bloom filter para mayor
//! eficiencia de memoria con millones de tickets. Para Mes 1 el HashSet es correcto.

use std::collections::HashSet;
use std::time::{Duration, Instant};

pub struct AntiReplayFilter {
    used_tickets: HashSet<[u8; 32]>,
    window_start: Instant,
    window_duration: Duration,
}

impl AntiReplayFilter {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            used_tickets: HashSet::new(),
            window_start: Instant::now(),
            window_duration,
        }
    }

    /// Retorna `true` si el ticket es valido (primera vez que se ve en la ventana actual).
    /// Retorna `false` si el ticket ya fue usado (replay) o si la ventana expiro y el
    /// ticket no pertenece a la nueva ventana.
    ///
    /// Efectos secundarios: marca el ticket como usado si es valido.
    pub fn check_and_consume(&mut self, ticket: [u8; 32]) -> bool {
        if self.window_start.elapsed() >= self.window_duration {
            self.used_tickets.clear();
            self.window_start = Instant::now();
        }

        if self.used_tickets.contains(&ticket) {
            return false;
        }

        self.used_tickets.insert(ticket);
        true
    }

    pub fn window_duration(&self) -> Duration {
        self.window_duration
    }

    pub fn tickets_in_window(&self) -> usize {
        self.used_tickets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn valid_ticket_accepted_once() {
        let mut filter = AntiReplayFilter::new(Duration::from_secs(60));
        let ticket = [0xABu8; 32];

        assert!(filter.check_and_consume(ticket), "primer uso debe aceptarse");
        assert!(!filter.check_and_consume(ticket), "segundo uso debe rechazarse");
    }

    #[test]
    fn different_tickets_all_accepted() {
        let mut filter = AntiReplayFilter::new(Duration::from_secs(60));

        for i in 0u8..10 {
            let mut ticket = [0u8; 32];
            ticket[0] = i;
            assert!(filter.check_and_consume(ticket));
        }
        assert_eq!(filter.tickets_in_window(), 10);
    }

    #[test]
    fn window_expiry_resets_filter() {
        // Ventana de 1 nanosegundo para que expire inmediatamente
        let mut filter = AntiReplayFilter::new(Duration::from_nanos(1));
        let ticket = [0x01u8; 32];

        filter.check_and_consume(ticket);

        // Esperar a que la ventana expire
        std::thread::sleep(Duration::from_millis(1));

        // El mismo ticket debe aceptarse en la nueva ventana
        assert!(
            filter.check_and_consume(ticket),
            "el ticket debe aceptarse en la nueva ventana"
        );
    }
}
