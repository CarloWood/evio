#pragma once

#include "utils/AIAlert.h"
#include "utils/print_using.h"
#include "utils/c_escape.h"
#include "evio/BinaryData.h"
#include "evio/DateTime.h"
#include <charconv>

namespace evio::protocol::xmlrpc {

template<typename T>
void initialize(T& member, std::string_view const& data)
{
  member.assign_from_xmlrpc_string(data);
}

template<>
inline void initialize(evio::BinaryData& binary_data, std::string_view const& base64_data)
{
  // Base64 does not need xml unescaping, since it does not contain any of '"<>&.
  binary_data.assign_from_base64(base64_data);
}

template<>
inline void initialize(evio::DateTime& date_time, std::string_view const& iso8601_data)
{
  // ISO8601 does not need xml unescaping, since it does not contain any of '"<>&.
  date_time.assign_from_iso8601_string(iso8601_data);
}

template<>
inline void initialize(int32_t& value, std::string_view const& int_data)
{
  auto result = std::from_chars(int_data.begin(), int_data.end(), value);
  if (result.ec == std::errc::invalid_argument || result.ptr != int_data.end())
  {
    THROW_ALERTC(result.ec, "Invalid characters [[DATA]] for integer", AIArgs("[DATA]", utils::print_using(int_data, utils::c_escape)));
  }
}

template<>
inline void initialize(double& value, std::string_view const& double_data)
{
  std::string data{double_data};
  try
  {
    value = std::stod(data);
  }
  catch (std::invalid_argument const& error)
  {
    THROW_ALERT("Invalid characters [[DATA]] for floating point", AIArgs("[DATA]", utils::print_using(double_data, utils::c_escape)));
  }
  catch (std::out_of_range  const& error)
  {
    THROW_ALERT("Data [[DATA]] is out of range for a double", AIArgs("[DATA]", utils::print_using(double_data, utils::c_escape)));
  }
}

template<>
inline void initialize(bool& value, std::string_view const& bool_data)
{
  if (bool_data == "true" || bool_data == "Y")
    value = true;
  else if (bool_data == "false" || bool_data == "N")
    value = false;
  else
  {
    THROW_ALERT("Invalid characters [[DATA]] for boolean", AIArgs("[DATA]", utils::print_using(bool_data, utils::c_escape)));
  }
}

template<>
inline void initialize(std::string& value, std::string_view const& string_data)
{
  value = string_data;
}

} // namespace evio::protocol::xmlrpc
