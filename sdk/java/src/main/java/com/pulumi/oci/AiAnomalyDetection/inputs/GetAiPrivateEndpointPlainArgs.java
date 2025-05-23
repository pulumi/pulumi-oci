// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.AiAnomalyDetection.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAiPrivateEndpointPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAiPrivateEndpointPlainArgs Empty = new GetAiPrivateEndpointPlainArgs();

    /**
     * Unique private reverse connection identifier.
     * 
     */
    @Import(name="aiPrivateEndpointId", required=true)
    private String aiPrivateEndpointId;

    /**
     * @return Unique private reverse connection identifier.
     * 
     */
    public String aiPrivateEndpointId() {
        return this.aiPrivateEndpointId;
    }

    private GetAiPrivateEndpointPlainArgs() {}

    private GetAiPrivateEndpointPlainArgs(GetAiPrivateEndpointPlainArgs $) {
        this.aiPrivateEndpointId = $.aiPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAiPrivateEndpointPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAiPrivateEndpointPlainArgs $;

        public Builder() {
            $ = new GetAiPrivateEndpointPlainArgs();
        }

        public Builder(GetAiPrivateEndpointPlainArgs defaults) {
            $ = new GetAiPrivateEndpointPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param aiPrivateEndpointId Unique private reverse connection identifier.
         * 
         * @return builder
         * 
         */
        public Builder aiPrivateEndpointId(String aiPrivateEndpointId) {
            $.aiPrivateEndpointId = aiPrivateEndpointId;
            return this;
        }

        public GetAiPrivateEndpointPlainArgs build() {
            if ($.aiPrivateEndpointId == null) {
                throw new MissingRequiredPropertyException("GetAiPrivateEndpointPlainArgs", "aiPrivateEndpointId");
            }
            return $;
        }
    }

}
