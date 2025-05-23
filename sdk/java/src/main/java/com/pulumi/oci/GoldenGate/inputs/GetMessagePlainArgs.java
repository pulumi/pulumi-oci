// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMessagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMessagePlainArgs Empty = new GetMessagePlainArgs();

    /**
     * A unique Deployment identifier.
     * 
     */
    @Import(name="deploymentId", required=true)
    private String deploymentId;

    /**
     * @return A unique Deployment identifier.
     * 
     */
    public String deploymentId() {
        return this.deploymentId;
    }

    private GetMessagePlainArgs() {}

    private GetMessagePlainArgs(GetMessagePlainArgs $) {
        this.deploymentId = $.deploymentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMessagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMessagePlainArgs $;

        public Builder() {
            $ = new GetMessagePlainArgs();
        }

        public Builder(GetMessagePlainArgs defaults) {
            $ = new GetMessagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deploymentId A unique Deployment identifier.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(String deploymentId) {
            $.deploymentId = deploymentId;
            return this;
        }

        public GetMessagePlainArgs build() {
            if ($.deploymentId == null) {
                throw new MissingRequiredPropertyException("GetMessagePlainArgs", "deploymentId");
            }
            return $;
        }
    }

}
