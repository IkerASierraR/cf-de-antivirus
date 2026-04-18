# application/__init__.py
# Marca este directorio como paquete Python.

from application.dtos import (
    ScanRequestDTO,
    ScanResponseDTO,
    QuarantineRequestDTO,
    QuarantineResponseDTO,
    CleanupRequestDTO,
    CleanupReportDTO
)

from application.quarantine_use_case import QuarantineUseCase
from application.cleanup_use_case import PCCleanupUseCase
from application.protection_use_case import RealTimeProtectionUseCase

__all__ = [
    "ScanRequestDTO",
    "ScanResponseDTO",
    "QuarantineRequestDTO",
    "QuarantineResponseDTO",
    "CleanupRequestDTO",
    "CleanupReportDTO",
    "QuarantineUseCase",
    "PCCleanupUseCase",
    "RealTimeProtectionUseCase"
]