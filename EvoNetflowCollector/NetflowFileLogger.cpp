#include "NetflowLogger.h"

NetflowFileLogger::NetflowFileLogger(const char* fileName)
{
	this->logFile.open(fileName, std::ofstream::out | std::ofstream::app);
}

NetflowFileLogger::~NetflowFileLogger()
{
	this->logFile.close();
}

// Writes a row of Netflow data to the opened log file.
const bool NetflowFileLogger::WriteNetflow(const std::string& netflowString)
{
	if (!this->logFile.is_open())
	{
		return false;
	}

	this->logFile << netflowString.c_str() << std::endl;
	this->logFile.flush();

	return true;
}

// Indicates whether the logfile is ready to be written to. This means: is the file open.
const bool NetflowFileLogger::IsReady() const
{
	return this->logFile.is_open();
}