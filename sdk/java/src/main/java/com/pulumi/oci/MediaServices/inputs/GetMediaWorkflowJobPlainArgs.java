// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MediaServices.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetMediaWorkflowJobPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetMediaWorkflowJobPlainArgs Empty = new GetMediaWorkflowJobPlainArgs();

    /**
     * Unique MediaWorkflowJob identifier.
     * 
     */
    @Import(name="mediaWorkflowJobId", required=true)
    private String mediaWorkflowJobId;

    /**
     * @return Unique MediaWorkflowJob identifier.
     * 
     */
    public String mediaWorkflowJobId() {
        return this.mediaWorkflowJobId;
    }

    private GetMediaWorkflowJobPlainArgs() {}

    private GetMediaWorkflowJobPlainArgs(GetMediaWorkflowJobPlainArgs $) {
        this.mediaWorkflowJobId = $.mediaWorkflowJobId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetMediaWorkflowJobPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetMediaWorkflowJobPlainArgs $;

        public Builder() {
            $ = new GetMediaWorkflowJobPlainArgs();
        }

        public Builder(GetMediaWorkflowJobPlainArgs defaults) {
            $ = new GetMediaWorkflowJobPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param mediaWorkflowJobId Unique MediaWorkflowJob identifier.
         * 
         * @return builder
         * 
         */
        public Builder mediaWorkflowJobId(String mediaWorkflowJobId) {
            $.mediaWorkflowJobId = mediaWorkflowJobId;
            return this;
        }

        public GetMediaWorkflowJobPlainArgs build() {
            $.mediaWorkflowJobId = Objects.requireNonNull($.mediaWorkflowJobId, "expected parameter 'mediaWorkflowJobId' to be non-null");
            return $;
        }
    }

}