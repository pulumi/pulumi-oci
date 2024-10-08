// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsConnectorDetailsArgs;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs Empty = new ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs();

    /**
     * The connector details required to connect to an Oracle cloud database.
     * 
     */
    @Import(name="connectorDetails")
    private @Nullable Output<ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsConnectorDetailsArgs> connectorDetails;

    /**
     * @return The connector details required to connect to an Oracle cloud database.
     * 
     */
    public Optional<Output<ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsConnectorDetailsArgs>> connectorDetails() {
        return Optional.ofNullable(this.connectorDetails);
    }

    /**
     * The name of the Database Management feature.
     * 
     */
    @Import(name="feature", required=true)
    private Output<String> feature;

    /**
     * @return The name of the Database Management feature.
     * 
     */
    public Output<String> feature() {
        return this.feature;
    }

    /**
     * The Oracle license model that applies to the external database.
     * 
     */
    @Import(name="licenseModel")
    private @Nullable Output<String> licenseModel;

    /**
     * @return The Oracle license model that applies to the external database.
     * 
     */
    public Optional<Output<String>> licenseModel() {
        return Optional.ofNullable(this.licenseModel);
    }

    private ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs() {}

    private ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs(ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs $) {
        this.connectorDetails = $.connectorDetails;
        this.feature = $.feature;
        this.licenseModel = $.licenseModel;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs $;

        public Builder() {
            $ = new ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs();
        }

        public Builder(ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs defaults) {
            $ = new ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectorDetails The connector details required to connect to an Oracle cloud database.
         * 
         * @return builder
         * 
         */
        public Builder connectorDetails(@Nullable Output<ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsConnectorDetailsArgs> connectorDetails) {
            $.connectorDetails = connectorDetails;
            return this;
        }

        /**
         * @param connectorDetails The connector details required to connect to an Oracle cloud database.
         * 
         * @return builder
         * 
         */
        public Builder connectorDetails(ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsConnectorDetailsArgs connectorDetails) {
            return connectorDetails(Output.of(connectorDetails));
        }

        /**
         * @param feature The name of the Database Management feature.
         * 
         * @return builder
         * 
         */
        public Builder feature(Output<String> feature) {
            $.feature = feature;
            return this;
        }

        /**
         * @param feature The name of the Database Management feature.
         * 
         * @return builder
         * 
         */
        public Builder feature(String feature) {
            return feature(Output.of(feature));
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(@Nullable Output<String> licenseModel) {
            $.licenseModel = licenseModel;
            return this;
        }

        /**
         * @param licenseModel The Oracle license model that applies to the external database.
         * 
         * @return builder
         * 
         */
        public Builder licenseModel(String licenseModel) {
            return licenseModel(Output.of(licenseModel));
        }

        public ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs build() {
            if ($.feature == null) {
                throw new MissingRequiredPropertyException("ExternalcontainerdatabaseExternalContainerDbmFeaturesManagementFeatureDetailsArgs", "feature");
            }
            return $;
        }
    }

}
