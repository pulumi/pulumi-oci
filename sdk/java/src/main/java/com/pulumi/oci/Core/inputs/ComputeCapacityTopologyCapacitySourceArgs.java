// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ComputeCapacityTopologyCapacitySourceArgs extends com.pulumi.resources.ResourceArgs {

    public static final ComputeCapacityTopologyCapacitySourceArgs Empty = new ComputeCapacityTopologyCapacitySourceArgs();

    /**
     * (Updatable) The capacity type of bare metal hosts.
     * 
     */
    @Import(name="capacityType", required=true)
    private Output<String> capacityType;

    /**
     * @return (Updatable) The capacity type of bare metal hosts.
     * 
     */
    public Output<String> capacityType() {
        return this.capacityType;
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of this capacity source.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of this capacity source.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    private ComputeCapacityTopologyCapacitySourceArgs() {}

    private ComputeCapacityTopologyCapacitySourceArgs(ComputeCapacityTopologyCapacitySourceArgs $) {
        this.capacityType = $.capacityType;
        this.compartmentId = $.compartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ComputeCapacityTopologyCapacitySourceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ComputeCapacityTopologyCapacitySourceArgs $;

        public Builder() {
            $ = new ComputeCapacityTopologyCapacitySourceArgs();
        }

        public Builder(ComputeCapacityTopologyCapacitySourceArgs defaults) {
            $ = new ComputeCapacityTopologyCapacitySourceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capacityType (Updatable) The capacity type of bare metal hosts.
         * 
         * @return builder
         * 
         */
        public Builder capacityType(Output<String> capacityType) {
            $.capacityType = capacityType;
            return this;
        }

        /**
         * @param capacityType (Updatable) The capacity type of bare metal hosts.
         * 
         * @return builder
         * 
         */
        public Builder capacityType(String capacityType) {
            return capacityType(Output.of(capacityType));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of this capacity source.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment of this capacity source.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public ComputeCapacityTopologyCapacitySourceArgs build() {
            if ($.capacityType == null) {
                throw new MissingRequiredPropertyException("ComputeCapacityTopologyCapacitySourceArgs", "capacityType");
            }
            return $;
        }
    }

}
