// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetLifecycleStagePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLifecycleStagePlainArgs Empty = new GetLifecycleStagePlainArgs();

    /**
     * The OCID of the lifecycle stage.
     * 
     */
    @Import(name="lifecycleStageId", required=true)
    private String lifecycleStageId;

    /**
     * @return The OCID of the lifecycle stage.
     * 
     */
    public String lifecycleStageId() {
        return this.lifecycleStageId;
    }

    private GetLifecycleStagePlainArgs() {}

    private GetLifecycleStagePlainArgs(GetLifecycleStagePlainArgs $) {
        this.lifecycleStageId = $.lifecycleStageId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLifecycleStagePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLifecycleStagePlainArgs $;

        public Builder() {
            $ = new GetLifecycleStagePlainArgs();
        }

        public Builder(GetLifecycleStagePlainArgs defaults) {
            $ = new GetLifecycleStagePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param lifecycleStageId The OCID of the lifecycle stage.
         * 
         * @return builder
         * 
         */
        public Builder lifecycleStageId(String lifecycleStageId) {
            $.lifecycleStageId = lifecycleStageId;
            return this;
        }

        public GetLifecycleStagePlainArgs build() {
            $.lifecycleStageId = Objects.requireNonNull($.lifecycleStageId, "expected parameter 'lifecycleStageId' to be non-null");
            return $;
        }
    }

}