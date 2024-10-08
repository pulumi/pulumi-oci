// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetInstancePoolLoadBalancerAttachmentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInstancePoolLoadBalancerAttachmentArgs Empty = new GetInstancePoolLoadBalancerAttachmentArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     */
    @Import(name="instancePoolId", required=true)
    private Output<String> instancePoolId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
     * 
     */
    public Output<String> instancePoolId() {
        return this.instancePoolId;
    }

    /**
     * The OCID of the load balancer attachment.
     * 
     */
    @Import(name="instancePoolLoadBalancerAttachmentId", required=true)
    private Output<String> instancePoolLoadBalancerAttachmentId;

    /**
     * @return The OCID of the load balancer attachment.
     * 
     */
    public Output<String> instancePoolLoadBalancerAttachmentId() {
        return this.instancePoolLoadBalancerAttachmentId;
    }

    private GetInstancePoolLoadBalancerAttachmentArgs() {}

    private GetInstancePoolLoadBalancerAttachmentArgs(GetInstancePoolLoadBalancerAttachmentArgs $) {
        this.instancePoolId = $.instancePoolId;
        this.instancePoolLoadBalancerAttachmentId = $.instancePoolLoadBalancerAttachmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInstancePoolLoadBalancerAttachmentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInstancePoolLoadBalancerAttachmentArgs $;

        public Builder() {
            $ = new GetInstancePoolLoadBalancerAttachmentArgs();
        }

        public Builder(GetInstancePoolLoadBalancerAttachmentArgs defaults) {
            $ = new GetInstancePoolLoadBalancerAttachmentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param instancePoolId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
         * 
         * @return builder
         * 
         */
        public Builder instancePoolId(Output<String> instancePoolId) {
            $.instancePoolId = instancePoolId;
            return this;
        }

        /**
         * @param instancePoolId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance pool.
         * 
         * @return builder
         * 
         */
        public Builder instancePoolId(String instancePoolId) {
            return instancePoolId(Output.of(instancePoolId));
        }

        /**
         * @param instancePoolLoadBalancerAttachmentId The OCID of the load balancer attachment.
         * 
         * @return builder
         * 
         */
        public Builder instancePoolLoadBalancerAttachmentId(Output<String> instancePoolLoadBalancerAttachmentId) {
            $.instancePoolLoadBalancerAttachmentId = instancePoolLoadBalancerAttachmentId;
            return this;
        }

        /**
         * @param instancePoolLoadBalancerAttachmentId The OCID of the load balancer attachment.
         * 
         * @return builder
         * 
         */
        public Builder instancePoolLoadBalancerAttachmentId(String instancePoolLoadBalancerAttachmentId) {
            return instancePoolLoadBalancerAttachmentId(Output.of(instancePoolLoadBalancerAttachmentId));
        }

        public GetInstancePoolLoadBalancerAttachmentArgs build() {
            if ($.instancePoolId == null) {
                throw new MissingRequiredPropertyException("GetInstancePoolLoadBalancerAttachmentArgs", "instancePoolId");
            }
            if ($.instancePoolLoadBalancerAttachmentId == null) {
                throw new MissingRequiredPropertyException("GetInstancePoolLoadBalancerAttachmentArgs", "instancePoolLoadBalancerAttachmentId");
            }
            return $;
        }
    }

}
