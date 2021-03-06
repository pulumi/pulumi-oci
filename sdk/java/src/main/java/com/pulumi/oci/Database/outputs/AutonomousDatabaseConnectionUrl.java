// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class AutonomousDatabaseConnectionUrl {
    /**
     * @return Oracle Application Express (APEX) URL.
     * 
     */
    private final @Nullable String apexUrl;
    /**
     * @return The URL of the Graph Studio for the Autonomous Database.
     * 
     */
    private final @Nullable String graphStudioUrl;
    /**
     * @return Oracle Machine Learning user management URL.
     * 
     */
    private final @Nullable String machineLearningUserManagementUrl;
    /**
     * @return Oracle SQL Developer Web URL.
     * 
     */
    private final @Nullable String sqlDevWebUrl;

    @CustomType.Constructor
    private AutonomousDatabaseConnectionUrl(
        @CustomType.Parameter("apexUrl") @Nullable String apexUrl,
        @CustomType.Parameter("graphStudioUrl") @Nullable String graphStudioUrl,
        @CustomType.Parameter("machineLearningUserManagementUrl") @Nullable String machineLearningUserManagementUrl,
        @CustomType.Parameter("sqlDevWebUrl") @Nullable String sqlDevWebUrl) {
        this.apexUrl = apexUrl;
        this.graphStudioUrl = graphStudioUrl;
        this.machineLearningUserManagementUrl = machineLearningUserManagementUrl;
        this.sqlDevWebUrl = sqlDevWebUrl;
    }

    /**
     * @return Oracle Application Express (APEX) URL.
     * 
     */
    public Optional<String> apexUrl() {
        return Optional.ofNullable(this.apexUrl);
    }
    /**
     * @return The URL of the Graph Studio for the Autonomous Database.
     * 
     */
    public Optional<String> graphStudioUrl() {
        return Optional.ofNullable(this.graphStudioUrl);
    }
    /**
     * @return Oracle Machine Learning user management URL.
     * 
     */
    public Optional<String> machineLearningUserManagementUrl() {
        return Optional.ofNullable(this.machineLearningUserManagementUrl);
    }
    /**
     * @return Oracle SQL Developer Web URL.
     * 
     */
    public Optional<String> sqlDevWebUrl() {
        return Optional.ofNullable(this.sqlDevWebUrl);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AutonomousDatabaseConnectionUrl defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String apexUrl;
        private @Nullable String graphStudioUrl;
        private @Nullable String machineLearningUserManagementUrl;
        private @Nullable String sqlDevWebUrl;

        public Builder() {
    	      // Empty
        }

        public Builder(AutonomousDatabaseConnectionUrl defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apexUrl = defaults.apexUrl;
    	      this.graphStudioUrl = defaults.graphStudioUrl;
    	      this.machineLearningUserManagementUrl = defaults.machineLearningUserManagementUrl;
    	      this.sqlDevWebUrl = defaults.sqlDevWebUrl;
        }

        public Builder apexUrl(@Nullable String apexUrl) {
            this.apexUrl = apexUrl;
            return this;
        }
        public Builder graphStudioUrl(@Nullable String graphStudioUrl) {
            this.graphStudioUrl = graphStudioUrl;
            return this;
        }
        public Builder machineLearningUserManagementUrl(@Nullable String machineLearningUserManagementUrl) {
            this.machineLearningUserManagementUrl = machineLearningUserManagementUrl;
            return this;
        }
        public Builder sqlDevWebUrl(@Nullable String sqlDevWebUrl) {
            this.sqlDevWebUrl = sqlDevWebUrl;
            return this;
        }        public AutonomousDatabaseConnectionUrl build() {
            return new AutonomousDatabaseConnectionUrl(apexUrl, graphStudioUrl, machineLearningUserManagementUrl, sqlDevWebUrl);
        }
    }
}
