// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetTrailSequenceArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTrailSequenceArgs Empty = new GetTrailSequenceArgs();

    /**
     * A unique Deployment identifier.
     * 
     */
    @Import(name="deploymentId", required=true)
    private Output<String> deploymentId;

    /**
     * @return A unique Deployment identifier.
     * 
     */
    public Output<String> deploymentId() {
        return this.deploymentId;
    }

    /**
     * A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * A Trail File identifier
     * 
     */
    @Import(name="trailFileId", required=true)
    private Output<String> trailFileId;

    /**
     * @return A Trail File identifier
     * 
     */
    public Output<String> trailFileId() {
        return this.trailFileId;
    }

    /**
     * A Trail Sequence identifier
     * 
     */
    @Import(name="trailSequenceId", required=true)
    private Output<String> trailSequenceId;

    /**
     * @return A Trail Sequence identifier
     * 
     */
    public Output<String> trailSequenceId() {
        return this.trailSequenceId;
    }

    private GetTrailSequenceArgs() {}

    private GetTrailSequenceArgs(GetTrailSequenceArgs $) {
        this.deploymentId = $.deploymentId;
        this.displayName = $.displayName;
        this.trailFileId = $.trailFileId;
        this.trailSequenceId = $.trailSequenceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTrailSequenceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTrailSequenceArgs $;

        public Builder() {
            $ = new GetTrailSequenceArgs();
        }

        public Builder(GetTrailSequenceArgs defaults) {
            $ = new GetTrailSequenceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param deploymentId A unique Deployment identifier.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(Output<String> deploymentId) {
            $.deploymentId = deploymentId;
            return this;
        }

        /**
         * @param deploymentId A unique Deployment identifier.
         * 
         * @return builder
         * 
         */
        public Builder deploymentId(String deploymentId) {
            return deploymentId(Output.of(deploymentId));
        }

        /**
         * @param displayName A filter to return only the resources that match the entire &#39;displayName&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only the resources that match the entire &#39;displayName&#39; given.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param trailFileId A Trail File identifier
         * 
         * @return builder
         * 
         */
        public Builder trailFileId(Output<String> trailFileId) {
            $.trailFileId = trailFileId;
            return this;
        }

        /**
         * @param trailFileId A Trail File identifier
         * 
         * @return builder
         * 
         */
        public Builder trailFileId(String trailFileId) {
            return trailFileId(Output.of(trailFileId));
        }

        /**
         * @param trailSequenceId A Trail Sequence identifier
         * 
         * @return builder
         * 
         */
        public Builder trailSequenceId(Output<String> trailSequenceId) {
            $.trailSequenceId = trailSequenceId;
            return this;
        }

        /**
         * @param trailSequenceId A Trail Sequence identifier
         * 
         * @return builder
         * 
         */
        public Builder trailSequenceId(String trailSequenceId) {
            return trailSequenceId(Output.of(trailSequenceId));
        }

        public GetTrailSequenceArgs build() {
            $.deploymentId = Objects.requireNonNull($.deploymentId, "expected parameter 'deploymentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.trailFileId = Objects.requireNonNull($.trailFileId, "expected parameter 'trailFileId' to be non-null");
            $.trailSequenceId = Objects.requireNonNull($.trailSequenceId, "expected parameter 'trailSequenceId' to be non-null");
            return $;
        }
    }

}