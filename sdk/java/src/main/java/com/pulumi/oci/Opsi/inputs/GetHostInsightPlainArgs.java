// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetHostInsightPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetHostInsightPlainArgs Empty = new GetHostInsightPlainArgs();

    /**
     * Unique host insight identifier
     * 
     */
    @Import(name="hostInsightId", required=true)
    private String hostInsightId;

    /**
     * @return Unique host insight identifier
     * 
     */
    public String hostInsightId() {
        return this.hostInsightId;
    }

    private GetHostInsightPlainArgs() {}

    private GetHostInsightPlainArgs(GetHostInsightPlainArgs $) {
        this.hostInsightId = $.hostInsightId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetHostInsightPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetHostInsightPlainArgs $;

        public Builder() {
            $ = new GetHostInsightPlainArgs();
        }

        public Builder(GetHostInsightPlainArgs defaults) {
            $ = new GetHostInsightPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param hostInsightId Unique host insight identifier
         * 
         * @return builder
         * 
         */
        public Builder hostInsightId(String hostInsightId) {
            $.hostInsightId = hostInsightId;
            return this;
        }

        public GetHostInsightPlainArgs build() {
            if ($.hostInsightId == null) {
                throw new MissingRequiredPropertyException("GetHostInsightPlainArgs", "hostInsightId");
            }
            return $;
        }
    }

}
