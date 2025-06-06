// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Sch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Sch.outputs.GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail {
    /**
     * @return The type of dimension value: static or evaluated.
     * 
     */
    private String kind;
    /**
     * @return The namespaces for the compartment-specific list.
     * 
     */
    private List<GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace> namespaces;

    private GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail() {}
    /**
     * @return The type of dimension value: static or evaluated.
     * 
     */
    public String kind() {
        return this.kind;
    }
    /**
     * @return The namespaces for the compartment-specific list.
     * 
     */
    public List<GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace> namespaces() {
        return this.namespaces;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String kind;
        private List<GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace> namespaces;
        public Builder() {}
        public Builder(GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kind = defaults.kind;
    	      this.namespaces = defaults.namespaces;
        }

        @CustomType.Setter
        public Builder kind(String kind) {
            if (kind == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail", "kind");
            }
            this.kind = kind;
            return this;
        }
        @CustomType.Setter
        public Builder namespaces(List<GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace> namespaces) {
            if (namespaces == null) {
              throw new MissingRequiredPropertyException("GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail", "namespaces");
            }
            this.namespaces = namespaces;
            return this;
        }
        public Builder namespaces(GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetailNamespace... namespaces) {
            return namespaces(List.of(namespaces));
        }
        public GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail build() {
            final var _resultValue = new GetServiceConnectorsServiceConnectorCollectionItemSourceMonitoringSourceNamespaceDetail();
            _resultValue.kind = kind;
            _resultValue.namespaces = namespaces;
            return _resultValue;
        }
    }
}
