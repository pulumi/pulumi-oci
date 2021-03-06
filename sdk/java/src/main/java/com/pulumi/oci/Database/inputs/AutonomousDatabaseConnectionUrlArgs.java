// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AutonomousDatabaseConnectionUrlArgs extends com.pulumi.resources.ResourceArgs {

    public static final AutonomousDatabaseConnectionUrlArgs Empty = new AutonomousDatabaseConnectionUrlArgs();

    /**
     * Oracle Application Express (APEX) URL.
     * 
     */
    @Import(name="apexUrl")
    private @Nullable Output<String> apexUrl;

    /**
     * @return Oracle Application Express (APEX) URL.
     * 
     */
    public Optional<Output<String>> apexUrl() {
        return Optional.ofNullable(this.apexUrl);
    }

    /**
     * The URL of the Graph Studio for the Autonomous Database.
     * 
     */
    @Import(name="graphStudioUrl")
    private @Nullable Output<String> graphStudioUrl;

    /**
     * @return The URL of the Graph Studio for the Autonomous Database.
     * 
     */
    public Optional<Output<String>> graphStudioUrl() {
        return Optional.ofNullable(this.graphStudioUrl);
    }

    /**
     * Oracle Machine Learning user management URL.
     * 
     */
    @Import(name="machineLearningUserManagementUrl")
    private @Nullable Output<String> machineLearningUserManagementUrl;

    /**
     * @return Oracle Machine Learning user management URL.
     * 
     */
    public Optional<Output<String>> machineLearningUserManagementUrl() {
        return Optional.ofNullable(this.machineLearningUserManagementUrl);
    }

    /**
     * Oracle SQL Developer Web URL.
     * 
     */
    @Import(name="sqlDevWebUrl")
    private @Nullable Output<String> sqlDevWebUrl;

    /**
     * @return Oracle SQL Developer Web URL.
     * 
     */
    public Optional<Output<String>> sqlDevWebUrl() {
        return Optional.ofNullable(this.sqlDevWebUrl);
    }

    private AutonomousDatabaseConnectionUrlArgs() {}

    private AutonomousDatabaseConnectionUrlArgs(AutonomousDatabaseConnectionUrlArgs $) {
        this.apexUrl = $.apexUrl;
        this.graphStudioUrl = $.graphStudioUrl;
        this.machineLearningUserManagementUrl = $.machineLearningUserManagementUrl;
        this.sqlDevWebUrl = $.sqlDevWebUrl;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AutonomousDatabaseConnectionUrlArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AutonomousDatabaseConnectionUrlArgs $;

        public Builder() {
            $ = new AutonomousDatabaseConnectionUrlArgs();
        }

        public Builder(AutonomousDatabaseConnectionUrlArgs defaults) {
            $ = new AutonomousDatabaseConnectionUrlArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param apexUrl Oracle Application Express (APEX) URL.
         * 
         * @return builder
         * 
         */
        public Builder apexUrl(@Nullable Output<String> apexUrl) {
            $.apexUrl = apexUrl;
            return this;
        }

        /**
         * @param apexUrl Oracle Application Express (APEX) URL.
         * 
         * @return builder
         * 
         */
        public Builder apexUrl(String apexUrl) {
            return apexUrl(Output.of(apexUrl));
        }

        /**
         * @param graphStudioUrl The URL of the Graph Studio for the Autonomous Database.
         * 
         * @return builder
         * 
         */
        public Builder graphStudioUrl(@Nullable Output<String> graphStudioUrl) {
            $.graphStudioUrl = graphStudioUrl;
            return this;
        }

        /**
         * @param graphStudioUrl The URL of the Graph Studio for the Autonomous Database.
         * 
         * @return builder
         * 
         */
        public Builder graphStudioUrl(String graphStudioUrl) {
            return graphStudioUrl(Output.of(graphStudioUrl));
        }

        /**
         * @param machineLearningUserManagementUrl Oracle Machine Learning user management URL.
         * 
         * @return builder
         * 
         */
        public Builder machineLearningUserManagementUrl(@Nullable Output<String> machineLearningUserManagementUrl) {
            $.machineLearningUserManagementUrl = machineLearningUserManagementUrl;
            return this;
        }

        /**
         * @param machineLearningUserManagementUrl Oracle Machine Learning user management URL.
         * 
         * @return builder
         * 
         */
        public Builder machineLearningUserManagementUrl(String machineLearningUserManagementUrl) {
            return machineLearningUserManagementUrl(Output.of(machineLearningUserManagementUrl));
        }

        /**
         * @param sqlDevWebUrl Oracle SQL Developer Web URL.
         * 
         * @return builder
         * 
         */
        public Builder sqlDevWebUrl(@Nullable Output<String> sqlDevWebUrl) {
            $.sqlDevWebUrl = sqlDevWebUrl;
            return this;
        }

        /**
         * @param sqlDevWebUrl Oracle SQL Developer Web URL.
         * 
         * @return builder
         * 
         */
        public Builder sqlDevWebUrl(String sqlDevWebUrl) {
            return sqlDevWebUrl(Output.of(sqlDevWebUrl));
        }

        public AutonomousDatabaseConnectionUrlArgs build() {
            return $;
        }
    }

}
