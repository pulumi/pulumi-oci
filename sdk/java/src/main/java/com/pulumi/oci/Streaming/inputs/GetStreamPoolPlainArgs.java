// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Streaming.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetStreamPoolPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetStreamPoolPlainArgs Empty = new GetStreamPoolPlainArgs();

    /**
     * The OCID of the stream pool.
     * 
     */
    @Import(name="streamPoolId", required=true)
    private String streamPoolId;

    /**
     * @return The OCID of the stream pool.
     * 
     */
    public String streamPoolId() {
        return this.streamPoolId;
    }

    private GetStreamPoolPlainArgs() {}

    private GetStreamPoolPlainArgs(GetStreamPoolPlainArgs $) {
        this.streamPoolId = $.streamPoolId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetStreamPoolPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetStreamPoolPlainArgs $;

        public Builder() {
            $ = new GetStreamPoolPlainArgs();
        }

        public Builder(GetStreamPoolPlainArgs defaults) {
            $ = new GetStreamPoolPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param streamPoolId The OCID of the stream pool.
         * 
         * @return builder
         * 
         */
        public Builder streamPoolId(String streamPoolId) {
            $.streamPoolId = streamPoolId;
            return this;
        }

        public GetStreamPoolPlainArgs build() {
            if ($.streamPoolId == null) {
                throw new MissingRequiredPropertyException("GetStreamPoolPlainArgs", "streamPoolId");
            }
            return $;
        }
    }

}
