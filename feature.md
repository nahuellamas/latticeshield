# Feature: SLH-DSA Offline Signing

## Por qué existe este feature

LatticeShield actualmente usa ML-DSA-65 (CRYSTALS-Dilithium) para toda la autenticación de identidad del servidor. ML-DSA es rápido, sus firmas son pequeñas (~3.3 KB), y es el estándar NIST FIPS 204 para la mayoría de los casos de uso.

El problema es que ML-DSA basa su seguridad en la matemática de redes (lattices). Esa matemática es relativamente nueva en el campo de batalla criptográfico. Si en 5 o 10 años se descubre un ataque eficiente contra problemas de lattices, ML-DSA cae — y con él toda la autenticación del proxy.

SLH-DSA (SPHINCS+, estandarizado como NIST FIPS 205 en agosto 2024) no usa lattices. Su única suposición de seguridad es que las funciones de hash (SHA-256, SHAKE256) sean resistentes a colisiones y pre-imágenes. Llevamos décadas atacando esas funciones y siguen en pie. Es el "seguro de vida" post-cuántico.

---

## Qué propone este feature

Agregar SLH-DSA al CLI de LatticeShield para **firma offline de artefactos de larga duración**:

- Firmas de binarios de release (`latticeshield-bridge`, `latticeshield-client`)
- Firma de bloques de configuración distribuidos a nodos
- Firma de logs de auditoría que deben ser verificables en 10+ años

### Subcomandos nuevos en `latticeshield`

```
latticeshield slh-keygen <dir>      # genera par de claves SLH-DSA
latticeshield slh-sign <file>       # firma un archivo
latticeshield slh-verify <file> <sig>  # verifica una firma
```

---

## Por qué NO va en el handshake del proxy

Esta es la decisión de diseño más importante del feature: **SLH-DSA nunca entra en el hot path**.

Los números reales hacen imposible usarlo en conexiones en vivo:

| Algoritmo         | Tamaño de firma | Velocidad sign |
| ----------------- | --------------- | -------------- |
| ML-DSA-65         | 3.3 KB          | ~0.5 ms        |
| SLH-DSA-SHA2-128s | 7.8 KB          | ~35 ms         |
| SLH-DSA-SHA2-128f | 17 KB           | ~5 ms          |

`SERVER_HELLO_SIGNED_LEN` ya son 4557 bytes hoy. Con SLH-DSA en el handshake ese mensaje sería entre 9 KB y 20 KB por conexión, más 35 ms de latencia de firma agregada por request. Con un connection pool activo eso destruye el throughput.

El handshake sigue en ML-DSA. Sin excepciones.

---

## Por qué no hay fallback automático

El feature.md original proponía que el proxy "conmute automáticamente a SLH-DSA si detecta una falla en ML-DSA". Eso es un antipatrón de seguridad conocido: **ataque de downgrade**.

Un atacante que pueda degradar el canal primero gatilla el fallback y fuerza el sistema a un modo que el atacante eligió. El único switch válido es manual, vía configuración explícita, con restart del proceso. Nunca en runtime.

---

## Parámetro set elegido: SLH-DSA-SHA2-128s

FIPS 205 define 12 variantes. Para firma offline de artefactos, el balance correcto es:

- **`-128s`** (small): 7.8 KB de firma, ~35 ms de sign — prioriza tamaño sobre velocidad
- **`-128f`** (fast): 17 KB de firma, ~5 ms de sign — prioriza velocidad sobre tamaño

Como la firma es offline (se hace una vez, no por cada request), el tamaño importa más que la velocidad. Elegimos **SHA2-128s**.

---

## Dependencia: `slh-dsa` (RustCrypto)

LatticeShield usa `libcrux-ml-dsa` porque es formalmente verificado. Para SLH-DSA, libcrux no tiene implementación disponible ni en su roadmap público.

La única opción viable hoy es el crate `slh-dsa` de RustCrypto:

- Pure Rust, FIPS 205 compliant
- Activo en crates.io/docs.rs
- **Sin auditoría independiente todavía**

**Decisión:** usar `slh-dsa` (RustCrypto) con disclaimer explícito en documentación: "pending independent audit". Es la práctica estándar de la industria mientras el ecosistema post-cuántico en Rust madura. El riesgo es aceptable porque el scope es estrictamente offline — no hay conexiones en vivo ni datos de usuario dependiendo de esta firma en tiempo real.

Cuando libcrux o RustCrypto publiquen una auditoría formal, migrar es un cambio de dependencia puntual.

---

## Scope hard boundaries

| ✅ Entra                                               | ❌ No entra                       |
| ------------------------------------------------------ | --------------------------------- |
| `latticeshield-crypto`: `signing::slh` module          | SLH-DSA en el handshake           |
| CLI subcomandos `slh-keygen`, `slh-sign`, `slh-verify` | Fallback automático en runtime    |
| Firma de artefactos offline                            | Cambios en `latticeshield-bridge` |
| Tests unitarios del módulo                             | Cambios en `latticeshield-client` |

---

## Estado

**Pendiente** — no está en el roadmap de releases activo. Se retoma cuando:

1. Se decide aceptar formalmente la dependencia `slh-dsa` (RustCrypto) sin auditoría, o
2. libcrux publica soporte para SLH-DSA.
