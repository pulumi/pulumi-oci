// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetMediaWorkflowPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMediaWorkflowPlainArgs Empty = new GetMediaWorkflowPlainArgs();

    /**
     * Unique MediaWorkflow identifier.
     * 
     */
    @Import(name="mediaWorkflowId", required=true)
    private String mediaWorkflowId;

    /**
     * @return Unique MediaWorkflow identifier.
     * 
     */
    public String mediaWorkflowId() {
        return this.mediaWorkflowId;
    }

    private GetMediaWorkflowPlainArgs() {}

    private GetMediaWorkflowPlainArgs(GetMediaWorkflowPlainArgs $) {
        this.mediaWorkflowId = $.mediaWorkflowId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMediaWorkflowPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMediaWorkflowPlainArgs $;

        public Builder() {
            $ = new GetMediaWorkflowPlainArgs();
        }

        public Builder(GetMediaWorkflowPlainArgs defaults) {
            $ = new GetMediaWorkflowPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param mediaWorkflowId Unique MediaWorkflow identifier.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowId(String mediaWorkflowId) {
            $.mediaWorkflowId = mediaWorkflowId;
            return this;
        }

        public GetMediaWorkflowPlainArgs build() {
            $.mediaWorkflowId = Objects.requireNonNull($.mediaWorkflowId, "expected parameter 'mediaWorkflowId' to be non-null");
            return $;
        }
    }

}