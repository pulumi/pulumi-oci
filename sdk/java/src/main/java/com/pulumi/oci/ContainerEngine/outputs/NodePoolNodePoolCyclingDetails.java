// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class NodePoolNodePoolCyclingDetails {
    /**
     * @return (Updatable) If nodes in the nodepool will be cycled to have new changes.
     * 
     */
    private @Nullable Boolean isNodeCyclingEnabled;
    /**
     * @return (Updatable) Maximum additional new compute instances that would be temporarily created and added to nodepool during the cycling nodepool process. OKE supports both integer and percentage input. Defaults to 1, Ranges from 0 to Nodepool size or 0% to 100%
     * 
     */
    private @Nullable String maximumSurge;
    /**
     * @return (Updatable) Maximum active nodes that would be terminated from nodepool during the cycling nodepool process. OKE supports both integer and percentage input. Defaults to 0, Ranges from 0 to Nodepool size or 0% to 100%
     * 
     */
    private @Nullable String maximumUnavailable;

    private NodePoolNodePoolCyclingDetails() {}
    /**
     * @return (Updatable) If nodes in the nodepool will be cycled to have new changes.
     * 
     */
    public Optional<Boolean> isNodeCyclingEnabled() {
        return Optional.ofNullable(this.isNodeCyclingEnabled);
    }
    /**
     * @return (Updatable) Maximum additional new compute instances that would be temporarily created and added to nodepool during the cycling nodepool process. OKE supports both integer and percentage input. Defaults to 1, Ranges from 0 to Nodepool size or 0% to 100%
     * 
     */
    public Optional<String> maximumSurge() {
        return Optional.ofNullable(this.maximumSurge);
    }
    /**
     * @return (Updatable) Maximum active nodes that would be terminated from nodepool during the cycling nodepool process. OKE supports both integer and percentage input. Defaults to 0, Ranges from 0 to Nodepool size or 0% to 100%
     * 
     */
    public Optional<String> maximumUnavailable() {
        return Optional.ofNullable(this.maximumUnavailable);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(NodePoolNodePoolCyclingDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isNodeCyclingEnabled;
        private @Nullable String maximumSurge;
        private @Nullable String maximumUnavailable;
        public Builder() {}
        public Builder(NodePoolNodePoolCyclingDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isNodeCyclingEnabled = defaults.isNodeCyclingEnabled;
    	      this.maximumSurge = defaults.maximumSurge;
    	      this.maximumUnavailable = defaults.maximumUnavailable;
        }

        @CustomType.Setter
        public Builder isNodeCyclingEnabled(@Nullable Boolean isNodeCyclingEnabled) {

            this.isNodeCyclingEnabled = isNodeCyclingEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder maximumSurge(@Nullable String maximumSurge) {

            this.maximumSurge = maximumSurge;
            return this;
        }
        @CustomType.Setter
        public Builder maximumUnavailable(@Nullable String maximumUnavailable) {

            this.maximumUnavailable = maximumUnavailable;
            return this;
        }
        public NodePoolNodePoolCyclingDetails build() {
            final var _resultValue = new NodePoolNodePoolCyclingDetails();
            _resultValue.isNodeCyclingEnabled = isNodeCyclingEnabled;
            _resultValue.maximumSurge = maximumSurge;
            _resultValue.maximumUnavailable = maximumUnavailable;
            return _resultValue;
        }
    }
}
