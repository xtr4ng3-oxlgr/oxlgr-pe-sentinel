# Entropía en OXLGR PE Sentinel

La entropía Shannon mide la distribución de bytes dentro de una región.

En análisis de binarios, valores altos pueden aparecer en:

- datos comprimidos,
- secciones cifradas,
- empaquetadores,
- recursos densos,
- blobs binarios,
- ofuscación,
- instaladores legítimos.

Valores bajos pueden indicar:

- código normal,
- datos repetitivos,
- tablas,
- padding,
- secciones vacías.

## Lectura orientativa

```text
0.0 - 4.5   Baja
4.5 - 6.8   Normal / media
6.8 - 7.2   Alta moderada
7.2 - 8.0   Alta
```

Una entropía alta no confirma malware. Solo indica que la región merece revisión.
