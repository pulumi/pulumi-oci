// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerInstances.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetContainerInstanceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetContainerInstanceArgs Empty = new GetContainerInstanceArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container instance.
     * 
     */
    @Import(name="containerInstanceId", required=true)
    private Output<String> containerInstanceId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container instance.
     * 
     */
    public Output<String> containerInstanceId() {
        return this.containerInstanceId;
    }

    private GetContainerInstanceArgs() {}

    private GetContainerInstanceArgs(GetContainerInstanceArgs $) {
        this.containerInstanceId = $.containerInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetContainerInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetContainerInstanceArgs $;

        public Builder() {
            $ = new GetContainerInstanceArgs();
        }

        public Builder(GetContainerInstanceArgs defaults) {
            $ = new GetContainerInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param containerInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container instance.
         * 
         * @return builder
         * 
         */
        public Builder containerInstanceId(Output<String> containerInstanceId) {
            $.containerInstanceId = containerInstanceId;
            return this;
        }

        /**
         * @param containerInstanceId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the container instance.
         * 
         * @return builder
         * 
         */
        public Builder containerInstanceId(String containerInstanceId) {
            return containerInstanceId(Output.of(containerInstanceId));
        }

        public GetContainerInstanceArgs build() {
            if ($.containerInstanceId == null) {
                throw new MissingRequiredPropertyException("GetContainerInstanceArgs", "containerInstanceId");
            }
            return $;
        }
    }

}
