// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Database.outputs.GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion {
    /**
     * @return A URL that points to a detailed description of the Autonomous Container Database version.
     * 
     */
    private String details;
    /**
     * @return The list of applications supported for the given version.
     * 
     */
    private List<GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp> supportedApps;
    /**
     * @return A valid Oracle Database version for provisioning an Autonomous Container Database.
     * 
     */
    private String version;

    private GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion() {}
    /**
     * @return A URL that points to a detailed description of the Autonomous Container Database version.
     * 
     */
    public String details() {
        return this.details;
    }
    /**
     * @return The list of applications supported for the given version.
     * 
     */
    public List<GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp> supportedApps() {
        return this.supportedApps;
    }
    /**
     * @return A valid Oracle Database version for provisioning an Autonomous Container Database.
     * 
     */
    public String version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String details;
        private List<GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp> supportedApps;
        private String version;
        public Builder() {}
        public Builder(GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.details = defaults.details;
    	      this.supportedApps = defaults.supportedApps;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder details(String details) {
            this.details = Objects.requireNonNull(details);
            return this;
        }
        @CustomType.Setter
        public Builder supportedApps(List<GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp> supportedApps) {
            this.supportedApps = Objects.requireNonNull(supportedApps);
            return this;
        }
        public Builder supportedApps(GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersionSupportedApp... supportedApps) {
            return supportedApps(List.of(supportedApps));
        }
        @CustomType.Setter
        public Builder version(String version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion build() {
            final var o = new GetAutonomousContainerDatabaseVersionsAutonomousContainerDatabaseVersion();
            o.details = details;
            o.supportedApps = supportedApps;
            o.version = version;
            return o;
        }
    }
}