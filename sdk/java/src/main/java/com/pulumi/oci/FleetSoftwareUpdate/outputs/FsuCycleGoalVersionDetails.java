// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetSoftwareUpdate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class FsuCycleGoalVersionDetails {
    /**
     * @return (Updatable) Goal home policy to use when Staging the Goal Version during patching. CREATE_NEW: Create a new DBHome (for Database Collections) for the specified image or version. USE_EXISTING: All database targets in the same VMCluster or CloudVmCluster will be moved to a shared database home.  If an existing home for the selected image or version is not found in the VM Cluster for a target database, then a new home will be created.  If more than one existing home for the selected image is found, then the home with the least number of databases will be used.  If multiple homes have the least number of databases, then a home will be selected at random.
     * 
     */
    private @Nullable String homePolicy;
    /**
     * @return (Updatable) Prefix name used for new DB home resources created as part of the Stage Action. Format: &lt;specified_prefix&gt;_&lt;timestamp&gt; If not specified, a default Oracle Cloud Infrastructure DB home resource will be generated for the new DB home resources created.
     * 
     */
    private @Nullable String newHomePrefix;
    /**
     * @return (Updatable) Target database software image OCID.
     * 
     */
    private @Nullable String softwareImageId;
    /**
     * @return (Updatable) Type of goal target version specified
     * 
     */
    private String type;
    /**
     * @return (Updatable) Target DB or GI version string for the Exadata Fleet Update Cycle.
     * 
     */
    private @Nullable String version;

    private FsuCycleGoalVersionDetails() {}
    /**
     * @return (Updatable) Goal home policy to use when Staging the Goal Version during patching. CREATE_NEW: Create a new DBHome (for Database Collections) for the specified image or version. USE_EXISTING: All database targets in the same VMCluster or CloudVmCluster will be moved to a shared database home.  If an existing home for the selected image or version is not found in the VM Cluster for a target database, then a new home will be created.  If more than one existing home for the selected image is found, then the home with the least number of databases will be used.  If multiple homes have the least number of databases, then a home will be selected at random.
     * 
     */
    public Optional<String> homePolicy() {
        return Optional.ofNullable(this.homePolicy);
    }
    /**
     * @return (Updatable) Prefix name used for new DB home resources created as part of the Stage Action. Format: &lt;specified_prefix&gt;_&lt;timestamp&gt; If not specified, a default Oracle Cloud Infrastructure DB home resource will be generated for the new DB home resources created.
     * 
     */
    public Optional<String> newHomePrefix() {
        return Optional.ofNullable(this.newHomePrefix);
    }
    /**
     * @return (Updatable) Target database software image OCID.
     * 
     */
    public Optional<String> softwareImageId() {
        return Optional.ofNullable(this.softwareImageId);
    }
    /**
     * @return (Updatable) Type of goal target version specified
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) Target DB or GI version string for the Exadata Fleet Update Cycle.
     * 
     */
    public Optional<String> version() {
        return Optional.ofNullable(this.version);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(FsuCycleGoalVersionDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String homePolicy;
        private @Nullable String newHomePrefix;
        private @Nullable String softwareImageId;
        private String type;
        private @Nullable String version;
        public Builder() {}
        public Builder(FsuCycleGoalVersionDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.homePolicy = defaults.homePolicy;
    	      this.newHomePrefix = defaults.newHomePrefix;
    	      this.softwareImageId = defaults.softwareImageId;
    	      this.type = defaults.type;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder homePolicy(@Nullable String homePolicy) {

            this.homePolicy = homePolicy;
            return this;
        }
        @CustomType.Setter
        public Builder newHomePrefix(@Nullable String newHomePrefix) {

            this.newHomePrefix = newHomePrefix;
            return this;
        }
        @CustomType.Setter
        public Builder softwareImageId(@Nullable String softwareImageId) {

            this.softwareImageId = softwareImageId;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("FsuCycleGoalVersionDetails", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder version(@Nullable String version) {

            this.version = version;
            return this;
        }
        public FsuCycleGoalVersionDetails build() {
            final var _resultValue = new FsuCycleGoalVersionDetails();
            _resultValue.homePolicy = homePolicy;
            _resultValue.newHomePrefix = newHomePrefix;
            _resultValue.softwareImageId = softwareImageId;
            _resultValue.type = type;
            _resultValue.version = version;
            return _resultValue;
        }
    }
}
