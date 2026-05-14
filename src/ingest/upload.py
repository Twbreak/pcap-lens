import io
from pathlib import Path
from dataclasses import dataclass

from src.config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE_BYTES


@dataclass
class UploadedFile:
    name: str
    size_bytes: int
    data: bytes

    @property
    def size_mb(self) -> float:
        return self.size_bytes / (1024 * 1024)


def validate_upload(file_obj) -> UploadedFile:
    """Validate a Streamlit uploaded file and return an UploadedFile.

    Raises ValueError for invalid extension, empty file, or oversized file.
    """
    name = file_obj.name
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Only .pcap files are accepted.")

    data = file_obj.read()
    size = len(data)

    if size == 0:
        raise ValueError("The uploaded file is empty.")
    if size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File size ({size / 1024 / 1024:.1f} MB) exceeds the "
            f"{MAX_FILE_SIZE_BYTES // 1024 // 1024} MB limit."
        )

    return UploadedFile(name=name, size_bytes=size, data=data)


def to_bytes_io(uploaded: UploadedFile) -> io.BytesIO:
    buf = io.BytesIO(uploaded.data)
    buf.name = uploaded.name
    return buf
