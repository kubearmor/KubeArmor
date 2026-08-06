#pragma once
// RAII-style guard for managing PFLT_FILE_NAME_INFORMATION resources.
// This class ensures that the FltReleaseFileNameInformation function is automatically called
// when the FilenameInformationGuard object goes out of scope, preventing resource leaks.
class FilenameInformationGuard
{
public:
    explicit FilenameInformationGuard(PFLT_FILE_NAME_INFORMATION* fileNameInfo) noexcept
        : m_fileNameInfo(fileNameInfo)
    {
    }

    ~FilenameInformationGuard()
    {
        if (*m_fileNameInfo)
        {
            FltReleaseFileNameInformation(*m_fileNameInfo);
            *m_fileNameInfo = nullptr;
        }
    }

    FilenameInformationGuard(const FilenameInformationGuard&) = delete;
    FilenameInformationGuard& operator=(const FilenameInformationGuard&) = delete;
    FilenameInformationGuard(FilenameInformationGuard&&) = delete;
    FilenameInformationGuard& operator=(FilenameInformationGuard&&) = delete;

private:
    PFLT_FILE_NAME_INFORMATION* m_fileNameInfo;
};
#pragma once
