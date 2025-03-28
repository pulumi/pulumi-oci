// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OneSubsription.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OneSubsription.outputs.GetInvoiceLineComputedUsagesFilter;
import com.pulumi.oci.OneSubsription.outputs.GetInvoiceLineComputedUsagesInvoicelineComputedUsage;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetInvoiceLineComputedUsagesResult {
    private String compartmentId;
    private @Nullable List<String> fields;
    private @Nullable List<GetInvoiceLineComputedUsagesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private String invoiceLineId;
    /**
     * @return The list of invoiceline_computed_usages.
     * 
     */
    private List<GetInvoiceLineComputedUsagesInvoicelineComputedUsage> invoicelineComputedUsages;

    private GetInvoiceLineComputedUsagesResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<String> fields() {
        return this.fields == null ? List.of() : this.fields;
    }
    public List<GetInvoiceLineComputedUsagesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String invoiceLineId() {
        return this.invoiceLineId;
    }
    /**
     * @return The list of invoiceline_computed_usages.
     * 
     */
    public List<GetInvoiceLineComputedUsagesInvoicelineComputedUsage> invoicelineComputedUsages() {
        return this.invoicelineComputedUsages;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInvoiceLineComputedUsagesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable List<String> fields;
        private @Nullable List<GetInvoiceLineComputedUsagesFilter> filters;
        private String id;
        private String invoiceLineId;
        private List<GetInvoiceLineComputedUsagesInvoicelineComputedUsage> invoicelineComputedUsages;
        public Builder() {}
        public Builder(GetInvoiceLineComputedUsagesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.fields = defaults.fields;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.invoiceLineId = defaults.invoiceLineId;
    	      this.invoicelineComputedUsages = defaults.invoicelineComputedUsages;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetInvoiceLineComputedUsagesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder fields(@Nullable List<String> fields) {

            this.fields = fields;
            return this;
        }
        public Builder fields(String... fields) {
            return fields(List.of(fields));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetInvoiceLineComputedUsagesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetInvoiceLineComputedUsagesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetInvoiceLineComputedUsagesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder invoiceLineId(String invoiceLineId) {
            if (invoiceLineId == null) {
              throw new MissingRequiredPropertyException("GetInvoiceLineComputedUsagesResult", "invoiceLineId");
            }
            this.invoiceLineId = invoiceLineId;
            return this;
        }
        @CustomType.Setter
        public Builder invoicelineComputedUsages(List<GetInvoiceLineComputedUsagesInvoicelineComputedUsage> invoicelineComputedUsages) {
            if (invoicelineComputedUsages == null) {
              throw new MissingRequiredPropertyException("GetInvoiceLineComputedUsagesResult", "invoicelineComputedUsages");
            }
            this.invoicelineComputedUsages = invoicelineComputedUsages;
            return this;
        }
        public Builder invoicelineComputedUsages(GetInvoiceLineComputedUsagesInvoicelineComputedUsage... invoicelineComputedUsages) {
            return invoicelineComputedUsages(List.of(invoicelineComputedUsages));
        }
        public GetInvoiceLineComputedUsagesResult build() {
            final var _resultValue = new GetInvoiceLineComputedUsagesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.fields = fields;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.invoiceLineId = invoiceLineId;
            _resultValue.invoicelineComputedUsages = invoicelineComputedUsages;
            return _resultValue;
        }
    }
}
