-- =============================================================
-- schema.sql — Base de datos del Antivirus Académico
-- Motor: MySQL 8.0+
-- Descripción: Base de datos de SOLO LECTURA que sirve como
--              watchlist de firmas y patrones sospechosos.
--              El sistema antivirus NUNCA modifica esta BD.
-- Uso: mysql -u root -p < schema.sql
-- =============================================================

CREATE DATABASE IF NOT EXISTS antivirus_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE antivirus_db;

-- =============================================================
-- TABLA 1: virus_signatures
-- Almacena firmas de malware conocido identificadas por hash SHA-256.
-- El scanner calcula el hash de cada archivo y consulta esta tabla.
-- =============================================================

CREATE TABLE IF NOT EXISTS virus_signatures (
    id            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    name          VARCHAR(150)    NOT NULL COMMENT 'Nombre del malware',
    hash_md5      CHAR(32)        NULL     COMMENT 'Hash MD5 (opcional, referencia)',
    hash_sha256   CHAR(64)        NOT NULL COMMENT 'Hash SHA-256 (clave de comparación principal)',
    threat_level  ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    category      VARCHAR(60)     NOT NULL COMMENT 'Tipo: ransomware, trojan, adware, worm, etc.',
    description   VARCHAR(300)    NULL     COMMENT 'Descripción breve del comportamiento',
    added_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_hash_sha256 (hash_sha256),
    INDEX idx_threat_level (threat_level),
    INDEX idx_category (category)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COMMENT='Firmas de malware conocido — solo lectura en tiempo de ejecución';


-- =============================================================
-- TABLA 2: suspicious_patterns
-- Almacena secuencias hexadecimales sospechosas detectables
-- dentro del contenido binario de un archivo.
-- =============================================================

CREATE TABLE IF NOT EXISTS suspicious_patterns (
    id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    pattern_name    VARCHAR(150)    NOT NULL COMMENT 'Nombre descriptivo del patrón',
    pattern_hex     VARCHAR(512)    NOT NULL COMMENT 'Secuencia hexadecimal a detectar en el archivo',
    file_extension  VARCHAR(20)     NULL     COMMENT 'Extensión objetivo (NULL = cualquier archivo)',
    threat_level    ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    description     VARCHAR(300)    NULL     COMMENT 'Técnica o comportamiento que representa',
    PRIMARY KEY (id),
    INDEX idx_extension (file_extension),
    INDEX idx_threat_level (threat_level)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COMMENT='Patrones de comportamiento sospechoso — solo lectura en tiempo de ejecución';


-- =============================================================
-- DATOS: virus_signatures
-- Solo los más representativos por categoría
-- =============================================================

INSERT INTO virus_signatures
    (name, hash_md5, hash_sha256, threat_level, category, description)
VALUES
-- TEST (estándar EICAR — archivo de prueba oficial antivirus)
(
    'EICAR-Test-File',
    '44d88612fea8a8f36de82e1278abb02f',
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    'LOW', 'test',
    'Archivo de prueba estándar EICAR. No es malware real. Usado para verificar que el antivirus funciona.'
),

-- RANSOMWARE
(
    'Ransomware.WannaCry.v1',
    '84c82835a5d21bbcf75a61706d8ab549',
    'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
    'CRITICAL', 'ransomware',
    'Variante original de WannaCry. Cifra archivos del usuario y exige rescate en Bitcoin.'
),
(
    'Ransomware.Locky',
    'aa4db4b5e7a8c9d1e2f3a4b5c6d7e8f9',
    'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
    'CRITICAL', 'ransomware',
    'Locky se propaga por macros maliciosas en documentos Office. Cifra más de 160 tipos de archivo.'
),

-- TROJAN
(
    'Trojan.AgentTesla',
    'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7',
    'b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    'HIGH', 'trojan',
    'Troyano de acceso remoto (RAT). Roba credenciales, capturas de pantalla y pulsaciones de teclado.'
),
(
    'Trojan.Emotet',
    'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
    'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3',
    'CRITICAL', 'trojan',
    'Emotet es un malware modular bancario/dropper. Considerado uno de los más peligrosos de la última década.'
),

-- WORM
(
    'Worm.Conficker.A',
    'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9',
    'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    'HIGH', 'worm',
    'Conficker explota la vulnerabilidad MS08-067 de Windows para propagarse por redes locales.'
),

-- ADWARE
(
    'Adware.OpenCandy',
    'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
    'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',
    'LOW', 'adware',
    'Adware que se instala junto a software gratuito. Muestra publicidad no deseada en el navegador.'
),

-- SPYWARE
(
    'Spyware.KeyloggerGeneric',
    'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1',
    'f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6',
    'HIGH', 'spyware',
    'Keylogger genérico que registra las pulsaciones del teclado y las envía a un servidor remoto.'
),

-- ROOTKIT
(
    'Rootkit.ZeroAccess',
    'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2',
    'a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7',
    'CRITICAL', 'rootkit',
    'Rootkit que se oculta en el sistema, deshabilita el firewall y convierte el equipo en bot para minería.'
);


-- =============================================================
-- DATOS: suspicious_patterns
-- Patrones de comportamiento detectables en contenido de archivos
-- =============================================================

INSERT INTO suspicious_patterns
    (pattern_name, pattern_hex, file_extension, threat_level, description)
VALUES
-- PowerShell ofuscado (muy común en ataques)
(
    'PowerShell-EncodedCommand',
    '706F7765727368656C6C202D656E636F646564436F6D6D616E64',
    '.ps1',
    'HIGH',
    'Comando PowerShell con parámetro -encodedCommand. Técnica clásica para ejecutar código ofuscado.'
),

-- Macro de Office con AutoOpen
(
    'VBA-AutoOpen-Macro',
    '537562204175746F4F70656E28',
    '.docm',
    'HIGH',
    'Macro VBA que se ejecuta automáticamente al abrir el documento. Vector frecuente de infección.'
),

-- Cabecera PE dentro de PDF (ejecutable disfrazado)
(
    'PE-Header-Inside-PDF',
    '4D5A90000300000004000000FFFF',
    '.pdf',
    'HIGH',
    'Cabecera de ejecutable Windows (MZ) dentro de un archivo PDF. Indica un ejecutable disfrazado.'
),

-- AutoRun en USB (archivo .inf malicioso)
(
    'AutoRun-USB-Dropper',
    '5B4175746F52756E5D0D0A4F70656E3D',
    '.inf',
    'MEDIUM',
    'Patrón de autorun.inf que lanza un ejecutable al insertar un dispositivo USB.'
),

-- Descarga desde Internet en script batch
(
    'Batch-WebDownload',
    '706F7765727368656C6C202D63202849',
    '.bat',
    'MEDIUM',
    'Script batch que usa PowerShell para descargar y ejecutar contenido desde Internet.'
),

-- Inyección de shellcode (patrón NOP sled)
(
    'NOP-Sled-Shellcode',
    '9090909090909090909090909090',
    NULL,
    'CRITICAL',
    'Secuencia de instrucciones NOP (0x90). Indicador común de shellcode de explotación de buffer overflow.'
),

-- Archivo ZIP con contraseña (evasión de análisis)
(
    'Password-Protected-ZIP',
    '504B030414000900',
    '.zip',
    'LOW',
    'Archivo ZIP protegido con contraseña. Técnica usada para evadir análisis automático de antivirus.'
),

-- Conexión a C2 en JavaScript ofuscado
(
    'JS-Obfuscated-Eval',
    '6576616C28756E657363617065',
    '.js',
    'HIGH',
    'Código JavaScript que usa eval() con unescape(). Patrón de ofuscación para ocultar código malicioso.'
);


-- =============================================================
-- VERIFICACIÓN FINAL
-- =============================================================

SELECT 'virus_signatures' AS tabla, COUNT(*) AS registros FROM virus_signatures
UNION ALL
SELECT 'suspicious_patterns', COUNT(*) FROM suspicious_patterns;
