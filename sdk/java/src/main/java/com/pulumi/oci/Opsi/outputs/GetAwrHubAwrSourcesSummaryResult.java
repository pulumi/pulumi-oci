// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opsi.outputs.GetAwrHubAwrSourcesSummaryItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAwrHubAwrSourcesSummaryResult {
    /**
     * @return AWR Hub OCID
     * 
     */
    private String awrHubId;
    private @Nullable String compartmentId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Array of AwrSource summary objects.
     * 
     */
    private List<GetAwrHubAwrSourcesSummaryItem> items;
    /**
     * @return Database name of the Source database for which AWR Data will be uploaded to AWR Hub.
     * 
     */
    private @Nullable String name;

    private GetAwrHubAwrSourcesSummaryResult() {}
    /**
     * @return AWR Hub OCID
     * 
     */
    public String awrHubId() {
        return this.awrHubId;
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
     * @return Array of AwrSource summary objects.
     * 
     */
    public List<GetAwrHubAwrSourcesSummaryItem> items() {
        return this.items;
    }
    /**
     * @return Database name of the Source database for which AWR Data will be uploaded to AWR Hub.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAwrHubAwrSourcesSummaryResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String awrHubId;
        private @Nullable String compartmentId;
        private String id;
        private List<GetAwrHubAwrSourcesSummaryItem> items;
        private @Nullable String name;
        public Builder() {}
        public Builder(GetAwrHubAwrSourcesSummaryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.awrHubId = defaults.awrHubId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder awrHubId(String awrHubId) {
            if (awrHubId == null) {
              throw new MissingRequiredPropertyException("GetAwrHubAwrSourcesSummaryResult", "awrHubId");
            }
            this.awrHubId = awrHubId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAwrHubAwrSourcesSummaryResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetAwrHubAwrSourcesSummaryItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetAwrHubAwrSourcesSummaryResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetAwrHubAwrSourcesSummaryItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        public GetAwrHubAwrSourcesSummaryResult build() {
            final var _resultValue = new GetAwrHubAwrSourcesSummaryResult();
            _resultValue.awrHubId = awrHubId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.id = id;
            _resultValue.items = items;
            _resultValue.name = name;
            return _resultValue;
        }
    }
}
