// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAwrHubArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAwrHubArgs Empty = new GetAwrHubArgs();

    /**
     * Unique Awr Hub identifier
     * 
     */
    @Import(name="awrHubId", required=true)
    private Output<String> awrHubId;

    /**
     * @return Unique Awr Hub identifier
     * 
     */
    public Output<String> awrHubId() {
        return this.awrHubId;
    }

    private GetAwrHubArgs() {}

    private GetAwrHubArgs(GetAwrHubArgs $) {
        this.awrHubId = $.awrHubId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAwrHubArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAwrHubArgs $;

        public Builder() {
            $ = new GetAwrHubArgs();
        }

        public Builder(GetAwrHubArgs defaults) {
            $ = new GetAwrHubArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param awrHubId Unique Awr Hub identifier
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(Output<String> awrHubId) {
            $.awrHubId = awrHubId;
            return this;
        }

        /**
         * @param awrHubId Unique Awr Hub identifier
         * 
         * @return builder
         * 
         */
        public Builder awrHubId(String awrHubId) {
            return awrHubId(Output.of(awrHubId));
        }

        public GetAwrHubArgs build() {
            $.awrHubId = Objects.requireNonNull($.awrHubId, "expected parameter 'awrHubId' to be non-null");
            return $;
        }
    }

}