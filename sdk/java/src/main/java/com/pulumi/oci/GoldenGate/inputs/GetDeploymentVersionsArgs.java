// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.GoldenGate.inputs.GetDeploymentVersionsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDeploymentVersionsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDeploymentVersionsArgs Empty = new GetDeploymentVersionsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
     * 
     */
    @Import(name="deploymentId")
    private @Nullable Output<String> deploymentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
     * 
     */
    public Optional<Output<String>> deploymentId() {
        return Optional.ofNullable(this.deploymentId);
    }

    /**
     * The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
     * 
     */
    @Import(name="deploymentType")
    private @Nullable Output<String> deploymentType;

    /**
     * @return The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
     * 
     */
    public Optional<Output<String>> deploymentType() {
        return Optional.ofNullable(this.deploymentType);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetDeploymentVersionsFilterArgs>> filters;

    public Optional<Output<List<GetDeploymentVersionsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetDeploymentVersionsArgs() {}

    private GetDeploymentVersionsArgs(GetDeploymentVersionsArgs $) {
        this.compartmentId = $.compartmentId;
        this.deploymentId = $.deploymentId;
        this.deploymentType = $.deploymentType;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDeploymentVersionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDeploymentVersionsArgs $;

        public Builder() {
            $ = new GetDeploymentVersionsArgs();
        }

        public Builder(GetDeploymentVersionsArgs defaults) {
            $ = new GetDeploymentVersionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param deploymentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(@Nullable Output<String> deploymentId) {
            $.deploymentId = deploymentId;
            return this;
        }

        /**
         * @param deploymentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment in which to list resources.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(String deploymentId) {
            return deploymentId(Output.of(deploymentId));
        }

        /**
         * @param deploymentType The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
         * 
         * @return builder
         * 
         */
        public Builder deploymentType(@Nullable Output<String> deploymentType) {
            $.deploymentType = deploymentType;
            return this;
        }

        /**
         * @param deploymentType The type of deployment, the value determines the exact &#39;type&#39; of the service executed in the deployment. Default value is DATABASE_ORACLE.
         * 
         * @return builder
         * 
         */
        public Builder deploymentType(String deploymentType) {
            return deploymentType(Output.of(deploymentType));
        }

        public Builder filters(@Nullable Output<List<GetDeploymentVersionsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetDeploymentVersionsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetDeploymentVersionsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetDeploymentVersionsArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDeploymentVersionsArgs", "compartmentId");
            }
            return $;
        }
    }

}
