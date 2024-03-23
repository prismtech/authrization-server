package com.prismtech.security.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class EmployeeDetailsResponse {
    String employeeId;
    String name;
    String employeeNo;
    String dateOfJoin;
    String email;
    String dateOfExit;
    String status;
    String designation;
}
