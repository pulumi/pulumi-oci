// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Queue.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetQueueArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetQueueArgs Empty = new GetQueueArgs();

    /**
     * The unique queue identifier.
     * 
     */
    @Import(name="queueId", required=true)
    private Output<String> queueId;

    /**
     * @return The unique queue identifier.
     * 
     */
    public Output<String> queueId() {
        return this.queueId;
    }

    private GetQueueArgs() {}

    private GetQueueArgs(GetQueueArgs $) {
        this.queueId = $.queueId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetQueueArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetQueueArgs $;

        public Builder() {
            $ = new GetQueueArgs();
        }

        public Builder(GetQueueArgs defaults) {
            $ = new GetQueueArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param queueId The unique queue identifier.
         * 
         * @return builder
         * 
         */
        public Builder queueId(Output<String> queueId) {
            $.queueId = queueId;
            return this;
        }

        /**
         * @param queueId The unique queue identifier.
         * 
         * @return builder
         * 
         */
        public Builder queueId(String queueId) {
            return queueId(Output.of(queueId));
        }

        public GetQueueArgs build() {
            if ($.queueId == null) {
                throw new MissingRequiredPropertyException("GetQueueArgs", "queueId");
            }
            return $;
        }
    }

}
