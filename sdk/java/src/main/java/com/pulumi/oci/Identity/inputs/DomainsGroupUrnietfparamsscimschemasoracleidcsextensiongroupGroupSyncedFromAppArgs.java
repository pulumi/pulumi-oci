// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs Empty = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs();

    /**
     * (Updatable) App Display Name
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="display")
    private @Nullable Output<String> display;

    /**
     * @return (Updatable) App Display Name
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> display() {
        return Optional.ofNullable(this.display);
    }

    /**
     * (Updatable) App URI
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) App URI
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) The type of the entity that created this Group.
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsDefaultValue: App
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The type of the entity that created this Group.
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * idcsDefaultValue: App
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) The ID of the App.
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value", required=true)
    private Output<String> value;

    /**
     * @return (Updatable) The ID of the App.
     * 
     * **Added In:** 18.4.2
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: true
     * * returned: default
     * * type: string
     * * uniqueness: none
     * 
     */
    public Output<String> value() {
        return this.value;
    }

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs() {}

    private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs $) {
        this.display = $.display;
        this.ref = $.ref;
        this.type = $.type;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs $;

        public Builder() {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs();
        }

        public Builder(DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs defaults) {
            $ = new DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param display (Updatable) App Display Name
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(@Nullable Output<String> display) {
            $.display = display;
            return this;
        }

        /**
         * @param display (Updatable) App Display Name
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder display(String display) {
            return display(Output.of(display));
        }

        /**
         * @param ref (Updatable) App URI
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) App URI
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param type (Updatable) The type of the entity that created this Group.
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsDefaultValue: App
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type of the entity that created this Group.
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * idcsDefaultValue: App
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param value (Updatable) The ID of the App.
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The ID of the App.
         * 
         * **Added In:** 18.4.2
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: true
         * * returned: default
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs", "type");
            }
            if ($.value == null) {
                throw new MissingRequiredPropertyException("DomainsGroupUrnietfparamsscimschemasoracleidcsextensiongroupGroupSyncedFromAppArgs", "value");
            }
            return $;
        }
    }

}
