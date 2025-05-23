// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter;
import com.pulumi.oci.Jms.outputs.GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetJavaDownloadsJavaLicenseAcceptanceRecordsResult {
    /**
     * @return The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
     * 
     */
    private String compartmentId;
    private @Nullable List<GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter> filters;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    private @Nullable String id;
    /**
     * @return The list of java_license_acceptance_record_collection.
     * 
     */
    private List<GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection> javaLicenseAcceptanceRecordCollections;
    /**
     * @return License type associated with the acceptance.
     * 
     */
    private @Nullable String licenseType;
    private @Nullable String searchByUser;
    private @Nullable String status;

    private GetJavaDownloadsJavaLicenseAcceptanceRecordsResult() {}
    /**
     * @return The tenancy [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the user accepting the license.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the principal.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The list of java_license_acceptance_record_collection.
     * 
     */
    public List<GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection> javaLicenseAcceptanceRecordCollections() {
        return this.javaLicenseAcceptanceRecordCollections;
    }
    /**
     * @return License type associated with the acceptance.
     * 
     */
    public Optional<String> licenseType() {
        return Optional.ofNullable(this.licenseType);
    }
    public Optional<String> searchByUser() {
        return Optional.ofNullable(this.searchByUser);
    }
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJavaDownloadsJavaLicenseAcceptanceRecordsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter> filters;
        private @Nullable String id;
        private List<GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection> javaLicenseAcceptanceRecordCollections;
        private @Nullable String licenseType;
        private @Nullable String searchByUser;
        private @Nullable String status;
        public Builder() {}
        public Builder(GetJavaDownloadsJavaLicenseAcceptanceRecordsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.javaLicenseAcceptanceRecordCollections = defaults.javaLicenseAcceptanceRecordCollections;
    	      this.licenseType = defaults.licenseType;
    	      this.searchByUser = defaults.searchByUser;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetJavaDownloadsJavaLicenseAcceptanceRecordsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetJavaDownloadsJavaLicenseAcceptanceRecordsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {

            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder javaLicenseAcceptanceRecordCollections(List<GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection> javaLicenseAcceptanceRecordCollections) {
            if (javaLicenseAcceptanceRecordCollections == null) {
              throw new MissingRequiredPropertyException("GetJavaDownloadsJavaLicenseAcceptanceRecordsResult", "javaLicenseAcceptanceRecordCollections");
            }
            this.javaLicenseAcceptanceRecordCollections = javaLicenseAcceptanceRecordCollections;
            return this;
        }
        public Builder javaLicenseAcceptanceRecordCollections(GetJavaDownloadsJavaLicenseAcceptanceRecordsJavaLicenseAcceptanceRecordCollection... javaLicenseAcceptanceRecordCollections) {
            return javaLicenseAcceptanceRecordCollections(List.of(javaLicenseAcceptanceRecordCollections));
        }
        @CustomType.Setter
        public Builder licenseType(@Nullable String licenseType) {

            this.licenseType = licenseType;
            return this;
        }
        @CustomType.Setter
        public Builder searchByUser(@Nullable String searchByUser) {

            this.searchByUser = searchByUser;
            return this;
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {

            this.status = status;
            return this;
        }
        public GetJavaDownloadsJavaLicenseAcceptanceRecordsResult build() {
            final var _resultValue = new GetJavaDownloadsJavaLicenseAcceptanceRecordsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.javaLicenseAcceptanceRecordCollections = javaLicenseAcceptanceRecordCollections;
            _resultValue.licenseType = licenseType;
            _resultValue.searchByUser = searchByUser;
            _resultValue.status = status;
            return _resultValue;
        }
    }
}
