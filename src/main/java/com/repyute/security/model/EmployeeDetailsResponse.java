package com.repyute.security.model;

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
    boolean employeeFound;
    String employeeId;
    String name;
    String employeeNo;
    String dateOfJoin;
    String email;
    String leavingDate;
    String status;
    String designation;
    long ctc;
    boolean incomeVerified;
    String eligibleToRehire;
    String exitFormalitiesCompleted;
    String reasonForLeaving;
}
