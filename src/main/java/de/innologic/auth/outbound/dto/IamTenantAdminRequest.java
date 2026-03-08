package de.innologic.auth.outbound.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IamTenantAdminRequest {

    private String tenantId;
    private String subjectId;
    private String subjectType;
    private List<String> roles;
    private Boolean tenantAdmin;

    public IamTenantAdminRequest() {
    }

    public IamTenantAdminRequest(String tenantId, String subjectId, String subjectType, List<String> roles, Boolean tenantAdmin) {
        this.tenantId = tenantId;
        this.subjectId = subjectId;
        this.subjectType = subjectType;
        this.roles = roles;
        this.tenantAdmin = tenantAdmin;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getSubjectId() {
        return subjectId;
    }

    public void setSubjectId(String subjectId) {
        this.subjectId = subjectId;
    }

    public String getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(String subjectType) {
        this.subjectType = subjectType;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public Boolean getTenantAdmin() {
        return tenantAdmin;
    }

    public void setTenantAdmin(Boolean tenantAdmin) {
        this.tenantAdmin = tenantAdmin;
    }
}

