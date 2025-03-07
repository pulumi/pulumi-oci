// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension {
    /**
     * @return The current state of the SQL collection.
     * 
     */
    private String state;
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    private String targetId;

    private GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension() {}
    /**
     * @return The current state of the SQL collection.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public String targetId() {
        return this.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String state;
        private String targetId;
        public Builder() {}
        public Builder(GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.state = defaults.state;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(String targetId) {
            if (targetId == null) {
              throw new MissingRequiredPropertyException("GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension", "targetId");
            }
            this.targetId = targetId;
            return this;
        }
        public GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension build() {
            final var _resultValue = new GetSqlCollectionAnalyticsSqlCollectionAnalyticsCollectionItemDimension();
            _resultValue.state = state;
            _resultValue.targetId = targetId;
            return _resultValue;
        }
    }
}
