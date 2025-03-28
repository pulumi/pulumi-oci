// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics {
    /**
     * @return (Updatable) The type discriminator.
     * 
     */
    private String kind;

    private ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics() {}
    /**
     * @return (Updatable) The type discriminator.
     * 
     */
    public String kind() {
        return this.kind;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String kind;
        public Builder() {}
        public Builder(ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kind = defaults.kind;
        }

        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics", "kind");
            }
            this.kind = kind;
            return this;
        }
        public ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics build() {
            final var _resultValue = new ConnectorSourceMonitoringSourceNamespaceDetailsNamespaceMetrics();
            _resultValue.kind = kind;
            return _resultValue;
        }
    }
}
