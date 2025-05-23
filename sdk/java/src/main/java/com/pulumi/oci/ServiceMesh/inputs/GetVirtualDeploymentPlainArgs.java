// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ServiceMesh.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetVirtualDeploymentPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVirtualDeploymentPlainArgs Empty = new GetVirtualDeploymentPlainArgs();

    /**
     * Unique VirtualDeployment identifier.
     * 
     */
    @Import(name="virtualDeploymentId", required=true)
    private String virtualDeploymentId;

    /**
     * @return Unique VirtualDeployment identifier.
     * 
     */
    public String virtualDeploymentId() {
        return this.virtualDeploymentId;
    }

    private GetVirtualDeploymentPlainArgs() {}

    private GetVirtualDeploymentPlainArgs(GetVirtualDeploymentPlainArgs $) {
        this.virtualDeploymentId = $.virtualDeploymentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVirtualDeploymentPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVirtualDeploymentPlainArgs $;

        public Builder() {
            $ = new GetVirtualDeploymentPlainArgs();
        }

        public Builder(GetVirtualDeploymentPlainArgs defaults) {
            $ = new GetVirtualDeploymentPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param virtualDeploymentId Unique VirtualDeployment identifier.
         * 
         * @return builder
         * 
         */
        public Builder virtualDeploymentId(String virtualDeploymentId) {
            $.virtualDeploymentId = virtualDeploymentId;
            return this;
        }

        public GetVirtualDeploymentPlainArgs build() {
            if ($.virtualDeploymentId == null) {
                throw new MissingRequiredPropertyException("GetVirtualDeploymentPlainArgs", "virtualDeploymentId");
            }
            return $;
        }
    }

}
