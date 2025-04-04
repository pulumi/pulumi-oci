// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetMediaWorkflowArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMediaWorkflowArgs Empty = new GetMediaWorkflowArgs();

    /**
     * Unique MediaWorkflow identifier.
     * 
     */
    @Import(name="mediaWorkflowId", required=true)
    private Output<String> mediaWorkflowId;

    /**
     * @return Unique MediaWorkflow identifier.
     * 
     */
    public Output<String> mediaWorkflowId() {
        return this.mediaWorkflowId;
    }

    private GetMediaWorkflowArgs() {}

    private GetMediaWorkflowArgs(GetMediaWorkflowArgs $) {
        this.mediaWorkflowId = $.mediaWorkflowId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMediaWorkflowArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMediaWorkflowArgs $;

        public Builder() {
            $ = new GetMediaWorkflowArgs();
        }

        public Builder(GetMediaWorkflowArgs defaults) {
            $ = new GetMediaWorkflowArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param mediaWorkflowId Unique MediaWorkflow identifier.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowId(Output<String> mediaWorkflowId) {
            $.mediaWorkflowId = mediaWorkflowId;
            return this;
        }

        /**
         * @param mediaWorkflowId Unique MediaWorkflow identifier.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowId(String mediaWorkflowId) {
            return mediaWorkflowId(Output.of(mediaWorkflowId));
        }

        public GetMediaWorkflowArgs build() {
            if ($.mediaWorkflowId == null) {
                throw new MissingRequiredPropertyException("GetMediaWorkflowArgs", "mediaWorkflowId");
            }
            return $;
        }
    }

}
