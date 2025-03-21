// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.MeteringComputation.inputs.UsageCarbonEmissionsQueryQueryDefinitionArgs;
import java.lang.String;
import java.util.Objects;


public final class UsageCarbonEmissionsQueryArgs extends com.pulumi.resources.ResourceArgs {

    public static final UsageCarbonEmissionsQueryArgs Empty = new UsageCarbonEmissionsQueryArgs();

    /**
     * The compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) The common fields for queries.
     * 
     */
    @Import(name="queryDefinition", required=true)
    private Output<UsageCarbonEmissionsQueryQueryDefinitionArgs> queryDefinition;

    /**
     * @return (Updatable) The common fields for queries.
     * 
     */
    public Output<UsageCarbonEmissionsQueryQueryDefinitionArgs> queryDefinition() {
        return this.queryDefinition;
    }

    private UsageCarbonEmissionsQueryArgs() {}

    private UsageCarbonEmissionsQueryArgs(UsageCarbonEmissionsQueryArgs $) {
        this.compartmentId = $.compartmentId;
        this.queryDefinition = $.queryDefinition;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(UsageCarbonEmissionsQueryArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private UsageCarbonEmissionsQueryArgs $;

        public Builder() {
            $ = new UsageCarbonEmissionsQueryArgs();
        }

        public Builder(UsageCarbonEmissionsQueryArgs defaults) {
            $ = new UsageCarbonEmissionsQueryArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param queryDefinition (Updatable) The common fields for queries.
         * 
         * @return builder
         * 
         */
        public Builder queryDefinition(Output<UsageCarbonEmissionsQueryQueryDefinitionArgs> queryDefinition) {
            $.queryDefinition = queryDefinition;
            return this;
        }

        /**
         * @param queryDefinition (Updatable) The common fields for queries.
         * 
         * @return builder
         * 
         */
        public Builder queryDefinition(UsageCarbonEmissionsQueryQueryDefinitionArgs queryDefinition) {
            return queryDefinition(Output.of(queryDefinition));
        }

        public UsageCarbonEmissionsQueryArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("UsageCarbonEmissionsQueryArgs", "compartmentId");
            }
            if ($.queryDefinition == null) {
                throw new MissingRequiredPropertyException("UsageCarbonEmissionsQueryArgs", "queryDefinition");
            }
            return $;
        }
    }

}
