// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ContainerEngine.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetClusterOptionResult {
    private final String clusterOptionId;
    private final @Nullable String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return Available Kubernetes versions.
     * 
     */
    private final List<String> kubernetesVersions;

    @CustomType.Constructor
    private GetClusterOptionResult(
        @CustomType.Parameter("clusterOptionId") String clusterOptionId,
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("kubernetesVersions") List<String> kubernetesVersions) {
        this.clusterOptionId = clusterOptionId;
        this.compartmentId = compartmentId;
        this.id = id;
        this.kubernetesVersions = kubernetesVersions;
    }

    public String clusterOptionId() {
        return this.clusterOptionId;
    }
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Available Kubernetes versions.
     * 
     */
    public List<String> kubernetesVersions() {
        return this.kubernetesVersions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetClusterOptionResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String clusterOptionId;
        private @Nullable String compartmentId;
        private String id;
        private List<String> kubernetesVersions;

        public Builder() {
    	      // Empty
        }

        public Builder(GetClusterOptionResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clusterOptionId = defaults.clusterOptionId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.kubernetesVersions = defaults.kubernetesVersions;
        }

        public Builder clusterOptionId(String clusterOptionId) {
            this.clusterOptionId = Objects.requireNonNull(clusterOptionId);
            return this;
        }
        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder kubernetesVersions(List<String> kubernetesVersions) {
            this.kubernetesVersions = Objects.requireNonNull(kubernetesVersions);
            return this;
        }
        public Builder kubernetesVersions(String... kubernetesVersions) {
            return kubernetesVersions(List.of(kubernetesVersions));
        }        public GetClusterOptionResult build() {
            return new GetClusterOptionResult(clusterOptionId, compartmentId, id, kubernetesVersions);
        }
    }
}
