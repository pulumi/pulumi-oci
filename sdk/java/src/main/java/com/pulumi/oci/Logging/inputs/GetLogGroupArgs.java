// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Logging.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetLogGroupArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetLogGroupArgs Empty = new GetLogGroupArgs();

    /**
     * OCID of a log group to work with.
     * 
     */
    @Import(name="logGroupId", required=true)
    private Output<String> logGroupId;

    /**
     * @return OCID of a log group to work with.
     * 
     */
    public Output<String> logGroupId() {
        return this.logGroupId;
    }

    private GetLogGroupArgs() {}

    private GetLogGroupArgs(GetLogGroupArgs $) {
        this.logGroupId = $.logGroupId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetLogGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetLogGroupArgs $;

        public Builder() {
            $ = new GetLogGroupArgs();
        }

        public Builder(GetLogGroupArgs defaults) {
            $ = new GetLogGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param logGroupId OCID of a log group to work with.
         * 
         * @return builder
         * 
         */
        public Builder logGroupId(Output<String> logGroupId) {
            $.logGroupId = logGroupId;
            return this;
        }

        /**
         * @param logGroupId OCID of a log group to work with.
         * 
         * @return builder
         * 
         */
        public Builder logGroupId(String logGroupId) {
            return logGroupId(Output.of(logGroupId));
        }

        public GetLogGroupArgs build() {
            $.logGroupId = Objects.requireNonNull($.logGroupId, "expected parameter 'logGroupId' to be non-null");
            return $;
        }
    }

}