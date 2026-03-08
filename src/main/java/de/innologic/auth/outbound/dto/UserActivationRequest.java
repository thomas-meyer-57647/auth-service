package de.innologic.auth.outbound.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserActivationRequest {

    private String userId;
    private String email;
    private String companyId;
    private String firstName;
    private String lastName;
    private String displayName;
    private String status;

    public UserActivationRequest() {
    }

    public UserActivationRequest(String userId, String email, String companyId, String firstName, String lastName, String displayName, String status) {
        this.userId = userId;
        this.email = email;
        this.companyId = companyId;
        this.firstName = firstName;
        this.lastName = lastName;
        this.displayName = displayName;
        this.status = status;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getCompanyId() {
        return companyId;
    }

    public void setCompanyId(String companyId) {
        this.companyId = companyId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}

