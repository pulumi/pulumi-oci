// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.GoldenGate.outputs.GetTrailFileItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetTrailFileResult {
    private String deploymentId;
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    private @Nullable String displayName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return An array of TrailFiles.
     * 
     */
    private List<GetTrailFileItem> items;
    /**
     * @return The time the data was last fetched from the deployment. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    private String timeLastFetched;
    /**
     * @return The TrailFile Id.
     * 
     */
    private String trailFileId;

    private GetTrailFileResult() {}
    public String deploymentId() {
        return this.deploymentId;
    }
    /**
     * @return An object&#39;s Display Name.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return An array of TrailFiles.
     * 
     */
    public List<GetTrailFileItem> items() {
        return this.items;
    }
    /**
     * @return The time the data was last fetched from the deployment. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
     * 
     */
    public String timeLastFetched() {
        return this.timeLastFetched;
    }
    /**
     * @return The TrailFile Id.
     * 
     */
    public String trailFileId() {
        return this.trailFileId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetTrailFileResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String deploymentId;
        private @Nullable String displayName;
        private String id;
        private List<GetTrailFileItem> items;
        private String timeLastFetched;
        private String trailFileId;
        public Builder() {}
        public Builder(GetTrailFileResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.deploymentId = defaults.deploymentId;
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.timeLastFetched = defaults.timeLastFetched;
    	      this.trailFileId = defaults.trailFileId;
        }

        @CustomType.Setter
        public Builder deploymentId(String deploymentId) {
            this.deploymentId = Objects.requireNonNull(deploymentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetTrailFileItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetTrailFileItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder timeLastFetched(String timeLastFetched) {
            this.timeLastFetched = Objects.requireNonNull(timeLastFetched);
            return this;
        }
        @CustomType.Setter
        public Builder trailFileId(String trailFileId) {
            this.trailFileId = Objects.requireNonNull(trailFileId);
            return this;
        }
        public GetTrailFileResult build() {
            final var o = new GetTrailFileResult();
            o.deploymentId = deploymentId;
            o.displayName = displayName;
            o.id = id;
            o.items = items;
            o.timeLastFetched = timeLastFetched;
            o.trailFileId = trailFileId;
            return o;
        }
    }
}