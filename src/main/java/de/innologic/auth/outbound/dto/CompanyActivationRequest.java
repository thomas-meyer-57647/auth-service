package de.innologic.auth.outbound.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class CompanyActivationRequest {

    private String companyId;
    private String companyName;
    private String status;
    private String timezone;
    private String countryCode;
    private String regionCode;
    private String locationId;
    private String headquarterLocationId;

    public CompanyActivationRequest() {
    }

    public CompanyActivationRequest(String companyId, String companyName, String status, String timezone, String countryCode, String regionCode, String locationId, String headquarterLocationId) {
        this.companyId = companyId;
        this.companyName = companyName;
        this.status = status;
        this.timezone = timezone;
        this.countryCode = countryCode;
        this.regionCode = regionCode;
        this.locationId = locationId;
        this.headquarterLocationId = headquarterLocationId;
    }

    public String getCompanyId() {
        return companyId;
    }

    public void setCompanyId(String companyId) {
        this.companyId = companyId;
    }

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public String getRegionCode() {
        return regionCode;
    }

    public void setRegionCode(String regionCode) {
        this.regionCode = regionCode;
    }

    public String getLocationId() {
        return locationId;
    }

    public void setLocationId(String locationId) {
        this.locationId = locationId;
    }

    public String getHeadquarterLocationId() {
        return headquarterLocationId;
    }

    public void setHeadquarterLocationId(String headquarterLocationId) {
        this.headquarterLocationId = headquarterLocationId;
    }
}

