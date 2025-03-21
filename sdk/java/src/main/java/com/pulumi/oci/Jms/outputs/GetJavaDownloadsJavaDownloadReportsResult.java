// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetJavaDownloadsJavaDownloadReportsFilter;
import com.pulumi.oci.Jms.outputs.GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetJavaDownloadsJavaDownloadReportsResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the Java download report.
     * 
     */
    private String compartmentId;
    /**
     * @return Display name for the Java download report.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetJavaDownloadsJavaDownloadReportsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of java_download_report_collection.
     * 
     */
    private List<GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection> javaDownloadReportCollections;
    private @Nullable String javaDownloadReportId;
    /**
     * @return The current state of the Java download report.
     * 
     */
    private @Nullable String state;

    private GetJavaDownloadsJavaDownloadReportsResult() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy scoped to the Java download report.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Display name for the Java download report.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetJavaDownloadsJavaDownloadReportsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of java_download_report_collection.
     * 
     */
    public List<GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection> javaDownloadReportCollections() {
        return this.javaDownloadReportCollections;
    }
    public Optional<String> javaDownloadReportId() {
        return Optional.ofNullable(this.javaDownloadReportId);
    }
    /**
     * @return The current state of the Java download report.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetJavaDownloadsJavaDownloadReportsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable List<GetJavaDownloadsJavaDownloadReportsFilter> filters;
        private String id;
        private List<GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection> javaDownloadReportCollections;
        private @Nullable String javaDownloadReportId;
        private @Nullable String state;
        public Builder() {}
        public Builder(GetJavaDownloadsJavaDownloadReportsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.javaDownloadReportCollections = defaults.javaDownloadReportCollections;
    	      this.javaDownloadReportId = defaults.javaDownloadReportId;
    	      this.state = defaults.state;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetJavaDownloadsJavaDownloadReportsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetJavaDownloadsJavaDownloadReportsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetJavaDownloadsJavaDownloadReportsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetJavaDownloadsJavaDownloadReportsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder javaDownloadReportCollections(List<GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection> javaDownloadReportCollections) {
            if (javaDownloadReportCollections == null) {
              throw new MissingRequiredPropertyException("GetJavaDownloadsJavaDownloadReportsResult", "javaDownloadReportCollections");
            }
            this.javaDownloadReportCollections = javaDownloadReportCollections;
            return this;
        }
        public Builder javaDownloadReportCollections(GetJavaDownloadsJavaDownloadReportsJavaDownloadReportCollection... javaDownloadReportCollections) {
            return javaDownloadReportCollections(List.of(javaDownloadReportCollections));
        }
        @CustomType.Setter
        public Builder javaDownloadReportId(@Nullable String javaDownloadReportId) {

            this.javaDownloadReportId = javaDownloadReportId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        public GetJavaDownloadsJavaDownloadReportsResult build() {
            final var _resultValue = new GetJavaDownloadsJavaDownloadReportsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.javaDownloadReportCollections = javaDownloadReportCollections;
            _resultValue.javaDownloadReportId = javaDownloadReportId;
            _resultValue.state = state;
            return _resultValue;
        }
    }
}
