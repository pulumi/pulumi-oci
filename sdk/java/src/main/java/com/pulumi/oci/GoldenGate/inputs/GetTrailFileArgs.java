// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetTrailFileArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetTrailFileArgs Empty = new GetTrailFileArgs();

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
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only the resources that match the entire &#39;displayName&#39; given.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
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

    private GetTrailFileArgs() {}

    private GetTrailFileArgs(GetTrailFileArgs $) {
        this.deploymentId = $.deploymentId;
        this.displayName = $.displayName;
        this.trailFileId = $.trailFileId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetTrailFileArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetTrailFileArgs $;

        public Builder() {
            $ = new GetTrailFileArgs();
        }

        public Builder(GetTrailFileArgs defaults) {
            $ = new GetTrailFileArgs(Objects.requireNonNull(defaults));
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
        public Builder displayName(@Nullable Output<String> displayName) {
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

        public GetTrailFileArgs build() {
            $.deploymentId = Objects.requireNonNull($.deploymentId, "expected parameter 'deploymentId' to be non-null");
            $.trailFileId = Objects.requireNonNull($.trailFileId, "expected parameter 'trailFileId' to be non-null");
            return $;
        }
    }

}