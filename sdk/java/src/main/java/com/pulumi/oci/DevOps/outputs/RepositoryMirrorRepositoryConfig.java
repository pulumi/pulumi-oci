// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DevOps.outputs.RepositoryMirrorRepositoryConfigTriggerSchedule;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RepositoryMirrorRepositoryConfig {
    /**
     * @return (Updatable) Upstream git repository connection identifer.
     * 
     */
    private @Nullable String connectorId;
    /**
     * @return (Updatable) URL of external repository you want to mirror.
     * 
     */
    private @Nullable String repositoryUrl;
    /**
     * @return (Updatable) Specifies a trigger schedule. Timing information for when to initiate automated syncs.
     * 
     */
    private @Nullable RepositoryMirrorRepositoryConfigTriggerSchedule triggerSchedule;

    private RepositoryMirrorRepositoryConfig() {}
    /**
     * @return (Updatable) Upstream git repository connection identifer.
     * 
     */
    public Optional<String> connectorId() {
        return Optional.ofNullable(this.connectorId);
    }
    /**
     * @return (Updatable) URL of external repository you want to mirror.
     * 
     */
    public Optional<String> repositoryUrl() {
        return Optional.ofNullable(this.repositoryUrl);
    }
    /**
     * @return (Updatable) Specifies a trigger schedule. Timing information for when to initiate automated syncs.
     * 
     */
    public Optional<RepositoryMirrorRepositoryConfigTriggerSchedule> triggerSchedule() {
        return Optional.ofNullable(this.triggerSchedule);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RepositoryMirrorRepositoryConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String connectorId;
        private @Nullable String repositoryUrl;
        private @Nullable RepositoryMirrorRepositoryConfigTriggerSchedule triggerSchedule;
        public Builder() {}
        public Builder(RepositoryMirrorRepositoryConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.connectorId = defaults.connectorId;
    	      this.repositoryUrl = defaults.repositoryUrl;
    	      this.triggerSchedule = defaults.triggerSchedule;
        }

        @CustomType.Setter
        public Builder connectorId(@Nullable String connectorId) {
            this.connectorId = connectorId;
            return this;
        }
        @CustomType.Setter
        public Builder repositoryUrl(@Nullable String repositoryUrl) {
            this.repositoryUrl = repositoryUrl;
            return this;
        }
        @CustomType.Setter
        public Builder triggerSchedule(@Nullable RepositoryMirrorRepositoryConfigTriggerSchedule triggerSchedule) {
            this.triggerSchedule = triggerSchedule;
            return this;
        }
        public RepositoryMirrorRepositoryConfig build() {
            final var o = new RepositoryMirrorRepositoryConfig();
            o.connectorId = connectorId;
            o.repositoryUrl = repositoryUrl;
            o.triggerSchedule = triggerSchedule;
            return o;
        }
    }
}