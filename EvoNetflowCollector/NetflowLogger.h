#include <iostream>
#include <fstream>

// Represents the base class of a Netflow log dumper. Netflow is collected and dumped, for example to a file.
class NetflowLogger
{
private:

public:
	NetflowLogger() { }
	virtual ~NetflowLogger() { }

	virtual const bool WriteNetflow(const std::string& netflowString) = 0;
	virtual const bool IsReady() const = 0;
};

// Represents the Netflow file dumper. It writes rows of text to a file.
class NetflowFileLogger : public NetflowLogger
{
private:
	std::ofstream logFile;
public:
	NetflowFileLogger(const char* fileName);
	~NetflowFileLogger();

	virtual const bool WriteNetflow(const std::string& netflowString);
	virtual const bool IsReady() const;
};