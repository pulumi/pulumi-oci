// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DataSafe.inputs.DiscoveryJobsResultModifiedAttributeArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DiscoveryJobsResultState extends com.pulumi.resources.ResourceArgs {

    public static final DiscoveryJobsResultState Empty = new DiscoveryJobsResultState();

    /**
     * Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     * 
     */
    @Import(name="appDefinedChildColumnKeys")
    private @Nullable Output<List<String>> appDefinedChildColumnKeys;

    /**
     * @return Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
     * 
     */
    public Optional<Output<List<String>>> appDefinedChildColumnKeys() {
        return Optional.ofNullable(this.appDefinedChildColumnKeys);
    }

    /**
     * The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
     * 
     */
    @Import(name="appName")
    private @Nullable Output<String> appName;

    /**
     * @return The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
     * 
     */
    public Optional<Output<String>> appName() {
        return Optional.ofNullable(this.appName);
    }

    /**
     * The name of the sensitive column.
     * 
     */
    @Import(name="columnName")
    private @Nullable Output<String> columnName;

    /**
     * @return The name of the sensitive column.
     * 
     */
    public Optional<Output<String>> columnName() {
        return Optional.ofNullable(this.columnName);
    }

    /**
     * The data type of the sensitive column.
     * 
     */
    @Import(name="dataType")
    private @Nullable Output<String> dataType;

    /**
     * @return The data type of the sensitive column.
     * 
     */
    public Optional<Output<String>> dataType() {
        return Optional.ofNullable(this.dataType);
    }

    /**
     * Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     * 
     */
    @Import(name="dbDefinedChildColumnKeys")
    private @Nullable Output<List<String>> dbDefinedChildColumnKeys;

    /**
     * @return Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
     * 
     */
    public Optional<Output<List<String>>> dbDefinedChildColumnKeys() {
        return Optional.ofNullable(this.dbDefinedChildColumnKeys);
    }

    /**
     * The OCID of the discovery job.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    @Import(name="discoveryJobId")
    private @Nullable Output<String> discoveryJobId;

    /**
     * @return The OCID of the discovery job.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    public Optional<Output<String>> discoveryJobId() {
        return Optional.ofNullable(this.discoveryJobId);
    }

    /**
     * The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    @Import(name="discoveryType")
    private @Nullable Output<String> discoveryType;

    /**
     * @return The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    public Optional<Output<String>> discoveryType() {
        return Optional.ofNullable(this.discoveryType);
    }

    /**
     * The estimated number of data values the column has in the associated database.
     * 
     */
    @Import(name="estimatedDataValueCount")
    private @Nullable Output<String> estimatedDataValueCount;

    /**
     * @return The estimated number of data values the column has in the associated database.
     * 
     */
    public Optional<Output<String>> estimatedDataValueCount() {
        return Optional.ofNullable(this.estimatedDataValueCount);
    }

    /**
     * Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     * 
     */
    @Import(name="isResultApplied")
    private @Nullable Output<Boolean> isResultApplied;

    /**
     * @return Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
     * 
     */
    public Optional<Output<Boolean>> isResultApplied() {
        return Optional.ofNullable(this.isResultApplied);
    }

    /**
     * The unique key that identifies the discovery result.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    @Import(name="key")
    private @Nullable Output<String> key;

    /**
     * @return The unique key that identifies the discovery result.
     * 
     * @deprecated
     * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
     * 
     */
    @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
    public Optional<Output<String>> key() {
        return Optional.ofNullable(this.key);
    }

    /**
     * The attributes of a sensitive column that have been modified in the target database. It&#39;s populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
     * 
     */
    @Import(name="modifiedAttributes")
    private @Nullable Output<List<DiscoveryJobsResultModifiedAttributeArgs>> modifiedAttributes;

    /**
     * @return The attributes of a sensitive column that have been modified in the target database. It&#39;s populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
     * 
     */
    public Optional<Output<List<DiscoveryJobsResultModifiedAttributeArgs>>> modifiedAttributes() {
        return Optional.ofNullable(this.modifiedAttributes);
    }

    /**
     * The database object that contains the sensitive column.
     * 
     */
    @Import(name="object")
    private @Nullable Output<String> object;

    /**
     * @return The database object that contains the sensitive column.
     * 
     */
    public Optional<Output<String>> object() {
        return Optional.ofNullable(this.object);
    }

    /**
     * The type of the database object that contains the sensitive column.
     * 
     */
    @Import(name="objectType")
    private @Nullable Output<String> objectType;

    /**
     * @return The type of the database object that contains the sensitive column.
     * 
     */
    public Optional<Output<String>> objectType() {
        return Optional.ofNullable(this.objectType);
    }

    /**
     * Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
     * 
     */
    @Import(name="parentColumnKeys")
    private @Nullable Output<List<String>> parentColumnKeys;

    /**
     * @return Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
     * 
     */
    public Optional<Output<List<String>>> parentColumnKeys() {
        return Optional.ofNullable(this.parentColumnKeys);
    }

    /**
     * Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     * 
     */
    @Import(name="plannedAction")
    private @Nullable Output<String> plannedAction;

    /**
     * @return Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
     * 
     */
    public Optional<Output<String>> plannedAction() {
        return Optional.ofNullable(this.plannedAction);
    }

    /**
     * The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     * 
     */
    @Import(name="relationType")
    private @Nullable Output<String> relationType;

    /**
     * @return The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
     * 
     */
    public Optional<Output<String>> relationType() {
        return Optional.ofNullable(this.relationType);
    }

    /**
     * Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
     * 
     */
    @Import(name="sampleDataValues")
    private @Nullable Output<List<String>> sampleDataValues;

    /**
     * @return Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
     * 
     */
    public Optional<Output<List<String>>> sampleDataValues() {
        return Optional.ofNullable(this.sampleDataValues);
    }

    /**
     * The database schema that contains the sensitive column.
     * 
     */
    @Import(name="schemaName")
    private @Nullable Output<String> schemaName;

    /**
     * @return The database schema that contains the sensitive column.
     * 
     */
    public Optional<Output<String>> schemaName() {
        return Optional.ofNullable(this.schemaName);
    }

    /**
     * The unique key that identifies the sensitive column represented by the discovery result.
     * 
     */
    @Import(name="sensitiveColumnkey")
    private @Nullable Output<String> sensitiveColumnkey;

    /**
     * @return The unique key that identifies the sensitive column represented by the discovery result.
     * 
     */
    public Optional<Output<String>> sensitiveColumnkey() {
        return Optional.ofNullable(this.sensitiveColumnkey);
    }

    /**
     * The OCID of the sensitive type associated with the sensitive column.
     * 
     */
    @Import(name="sensitiveTypeId")
    private @Nullable Output<String> sensitiveTypeId;

    /**
     * @return The OCID of the sensitive type associated with the sensitive column.
     * 
     */
    public Optional<Output<String>> sensitiveTypeId() {
        return Optional.ofNullable(this.sensitiveTypeId);
    }

    private DiscoveryJobsResultState() {}

    private DiscoveryJobsResultState(DiscoveryJobsResultState $) {
        this.appDefinedChildColumnKeys = $.appDefinedChildColumnKeys;
        this.appName = $.appName;
        this.columnName = $.columnName;
        this.dataType = $.dataType;
        this.dbDefinedChildColumnKeys = $.dbDefinedChildColumnKeys;
        this.discoveryJobId = $.discoveryJobId;
        this.discoveryType = $.discoveryType;
        this.estimatedDataValueCount = $.estimatedDataValueCount;
        this.isResultApplied = $.isResultApplied;
        this.key = $.key;
        this.modifiedAttributes = $.modifiedAttributes;
        this.object = $.object;
        this.objectType = $.objectType;
        this.parentColumnKeys = $.parentColumnKeys;
        this.plannedAction = $.plannedAction;
        this.relationType = $.relationType;
        this.sampleDataValues = $.sampleDataValues;
        this.schemaName = $.schemaName;
        this.sensitiveColumnkey = $.sensitiveColumnkey;
        this.sensitiveTypeId = $.sensitiveTypeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DiscoveryJobsResultState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DiscoveryJobsResultState $;

        public Builder() {
            $ = new DiscoveryJobsResultState();
        }

        public Builder(DiscoveryJobsResultState defaults) {
            $ = new DiscoveryJobsResultState(Objects.requireNonNull(defaults));
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(@Nullable Output<List<String>> appDefinedChildColumnKeys) {
            $.appDefinedChildColumnKeys = appDefinedChildColumnKeys;
            return this;
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(List<String> appDefinedChildColumnKeys) {
            return appDefinedChildColumnKeys(Output.of(appDefinedChildColumnKeys));
        }

        /**
         * @param appDefinedChildColumnKeys Unique keys identifying the columns that are application-level (non-dictionary) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder appDefinedChildColumnKeys(String... appDefinedChildColumnKeys) {
            return appDefinedChildColumnKeys(List.of(appDefinedChildColumnKeys));
        }

        /**
         * @param appName The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
         * 
         * @return builder
         * 
         */
        public Builder appName(@Nullable Output<String> appName) {
            $.appName = appName;
            return this;
        }

        /**
         * @param appName The name of the application. An application is an entity that is identified by a schema and stores sensitive information for that schema. Its value will be same as schemaName, if no value is passed.
         * 
         * @return builder
         * 
         */
        public Builder appName(String appName) {
            return appName(Output.of(appName));
        }

        /**
         * @param columnName The name of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(@Nullable Output<String> columnName) {
            $.columnName = columnName;
            return this;
        }

        /**
         * @param columnName The name of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder columnName(String columnName) {
            return columnName(Output.of(columnName));
        }

        /**
         * @param dataType The data type of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dataType(@Nullable Output<String> dataType) {
            $.dataType = dataType;
            return this;
        }

        /**
         * @param dataType The data type of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dataType(String dataType) {
            return dataType(Output.of(dataType));
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(@Nullable Output<List<String>> dbDefinedChildColumnKeys) {
            $.dbDefinedChildColumnKeys = dbDefinedChildColumnKeys;
            return this;
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(List<String> dbDefinedChildColumnKeys) {
            return dbDefinedChildColumnKeys(Output.of(dbDefinedChildColumnKeys));
        }

        /**
         * @param dbDefinedChildColumnKeys Unique keys identifying the columns that are database-level (dictionary-defined) children of the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder dbDefinedChildColumnKeys(String... dbDefinedChildColumnKeys) {
            return dbDefinedChildColumnKeys(List.of(dbDefinedChildColumnKeys));
        }

        /**
         * @param discoveryJobId The OCID of the discovery job.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder discoveryJobId(@Nullable Output<String> discoveryJobId) {
            $.discoveryJobId = discoveryJobId;
            return this;
        }

        /**
         * @param discoveryJobId The OCID of the discovery job.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder discoveryJobId(String discoveryJobId) {
            return discoveryJobId(Output.of(discoveryJobId));
        }

        /**
         * @param discoveryType The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder discoveryType(@Nullable Output<String> discoveryType) {
            $.discoveryType = discoveryType;
            return this;
        }

        /**
         * @param discoveryType The type of the discovery result. It can be one of the following three types: NEW: A new sensitive column in the target database that is not in the sensitive data model. DELETED: A column that is present in the sensitive data model but has been deleted from the target database. MODIFIED: A column that is present in the target database as well as the sensitive data model but some of its attributes have been modified.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder discoveryType(String discoveryType) {
            return discoveryType(Output.of(discoveryType));
        }

        /**
         * @param estimatedDataValueCount The estimated number of data values the column has in the associated database.
         * 
         * @return builder
         * 
         */
        public Builder estimatedDataValueCount(@Nullable Output<String> estimatedDataValueCount) {
            $.estimatedDataValueCount = estimatedDataValueCount;
            return this;
        }

        /**
         * @param estimatedDataValueCount The estimated number of data values the column has in the associated database.
         * 
         * @return builder
         * 
         */
        public Builder estimatedDataValueCount(String estimatedDataValueCount) {
            return estimatedDataValueCount(Output.of(estimatedDataValueCount));
        }

        /**
         * @param isResultApplied Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder isResultApplied(@Nullable Output<Boolean> isResultApplied) {
            $.isResultApplied = isResultApplied;
            return this;
        }

        /**
         * @param isResultApplied Indicates if the discovery result has been processed. You can update this attribute using the PatchDiscoveryJobResults operation to track whether the discovery result has already been processed and applied to the sensitive data model.
         * 
         * @return builder
         * 
         */
        public Builder isResultApplied(Boolean isResultApplied) {
            return isResultApplied(Output.of(isResultApplied));
        }

        /**
         * @param key The unique key that identifies the discovery result.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder key(@Nullable Output<String> key) {
            $.key = key;
            return this;
        }

        /**
         * @param key The unique key that identifies the discovery result.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_data_safe_discovery_jobs_result&#39; resource has been deprecated. It is no longer supported.
         * 
         */
        @Deprecated /* The 'oci_data_safe_discovery_jobs_result' resource has been deprecated. It is no longer supported. */
        public Builder key(String key) {
            return key(Output.of(key));
        }

        /**
         * @param modifiedAttributes The attributes of a sensitive column that have been modified in the target database. It&#39;s populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
         * 
         * @return builder
         * 
         */
        public Builder modifiedAttributes(@Nullable Output<List<DiscoveryJobsResultModifiedAttributeArgs>> modifiedAttributes) {
            $.modifiedAttributes = modifiedAttributes;
            return this;
        }

        /**
         * @param modifiedAttributes The attributes of a sensitive column that have been modified in the target database. It&#39;s populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
         * 
         * @return builder
         * 
         */
        public Builder modifiedAttributes(List<DiscoveryJobsResultModifiedAttributeArgs> modifiedAttributes) {
            return modifiedAttributes(Output.of(modifiedAttributes));
        }

        /**
         * @param modifiedAttributes The attributes of a sensitive column that have been modified in the target database. It&#39;s populated only in the case of MODIFIED discovery results and shows the new values of the modified attributes.
         * 
         * @return builder
         * 
         */
        public Builder modifiedAttributes(DiscoveryJobsResultModifiedAttributeArgs... modifiedAttributes) {
            return modifiedAttributes(List.of(modifiedAttributes));
        }

        /**
         * @param object The database object that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder object(@Nullable Output<String> object) {
            $.object = object;
            return this;
        }

        /**
         * @param object The database object that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder object(String object) {
            return object(Output.of(object));
        }

        /**
         * @param objectType The type of the database object that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder objectType(@Nullable Output<String> objectType) {
            $.objectType = objectType;
            return this;
        }

        /**
         * @param objectType The type of the database object that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder objectType(String objectType) {
            return objectType(Output.of(objectType));
        }

        /**
         * @param parentColumnKeys Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
         * 
         * @return builder
         * 
         */
        public Builder parentColumnKeys(@Nullable Output<List<String>> parentColumnKeys) {
            $.parentColumnKeys = parentColumnKeys;
            return this;
        }

        /**
         * @param parentColumnKeys Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
         * 
         * @return builder
         * 
         */
        public Builder parentColumnKeys(List<String> parentColumnKeys) {
            return parentColumnKeys(Output.of(parentColumnKeys));
        }

        /**
         * @param parentColumnKeys Unique keys identifying the columns that are parents of the sensitive column. At present, it tracks a single parent only.
         * 
         * @return builder
         * 
         */
        public Builder parentColumnKeys(String... parentColumnKeys) {
            return parentColumnKeys(List.of(parentColumnKeys));
        }

        /**
         * @param plannedAction Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
         * 
         * @return builder
         * 
         */
        public Builder plannedAction(@Nullable Output<String> plannedAction) {
            $.plannedAction = plannedAction;
            return this;
        }

        /**
         * @param plannedAction Specifies how to process the discovery result. It&#39;s set to NONE by default. Use the PatchDiscoveryJobResults operation to update this attribute. You can choose one of the following options: ACCEPT: To accept the discovery result and update the sensitive data model to reflect the changes. REJECT: To reject the discovery result so that it doesn&#39;t change the sensitive data model. INVALIDATE: To invalidate a newly discovered column. It adds the column to the sensitive data model but marks it as invalid. It helps track false positives and ensure that they aren&#39;t reported by future discovery jobs. After specifying the planned action, you can use the ApplyDiscoveryJobResults operation to automatically process the discovery results.
         * 
         * @return builder
         * 
         */
        public Builder plannedAction(String plannedAction) {
            return plannedAction(Output.of(plannedAction));
        }

        /**
         * @param relationType The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
         * 
         * @return builder
         * 
         */
        public Builder relationType(@Nullable Output<String> relationType) {
            $.relationType = relationType;
            return this;
        }

        /**
         * @param relationType The type of referential relationship the sensitive column has with its parent. NONE indicates that the sensitive column does not have a parent. DB_DEFINED indicates that the relationship is defined in the database dictionary. APP_DEFINED indicates that the relationship is defined at the application level and not in the database dictionary.
         * 
         * @return builder
         * 
         */
        public Builder relationType(String relationType) {
            return relationType(Output.of(relationType));
        }

        /**
         * @param sampleDataValues Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder sampleDataValues(@Nullable Output<List<String>> sampleDataValues) {
            $.sampleDataValues = sampleDataValues;
            return this;
        }

        /**
         * @param sampleDataValues Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder sampleDataValues(List<String> sampleDataValues) {
            return sampleDataValues(Output.of(sampleDataValues));
        }

        /**
         * @param sampleDataValues Original data values collected for the sensitive column from the associated database. Sample data helps review the column and ensure that it actually contains sensitive data. Note that sample data is retrieved by a data discovery job only if the isSampleDataCollectionEnabled attribute is set to true. At present, only one data value is collected per sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder sampleDataValues(String... sampleDataValues) {
            return sampleDataValues(List.of(sampleDataValues));
        }

        /**
         * @param schemaName The database schema that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(@Nullable Output<String> schemaName) {
            $.schemaName = schemaName;
            return this;
        }

        /**
         * @param schemaName The database schema that contains the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder schemaName(String schemaName) {
            return schemaName(Output.of(schemaName));
        }

        /**
         * @param sensitiveColumnkey The unique key that identifies the sensitive column represented by the discovery result.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveColumnkey(@Nullable Output<String> sensitiveColumnkey) {
            $.sensitiveColumnkey = sensitiveColumnkey;
            return this;
        }

        /**
         * @param sensitiveColumnkey The unique key that identifies the sensitive column represented by the discovery result.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveColumnkey(String sensitiveColumnkey) {
            return sensitiveColumnkey(Output.of(sensitiveColumnkey));
        }

        /**
         * @param sensitiveTypeId The OCID of the sensitive type associated with the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(@Nullable Output<String> sensitiveTypeId) {
            $.sensitiveTypeId = sensitiveTypeId;
            return this;
        }

        /**
         * @param sensitiveTypeId The OCID of the sensitive type associated with the sensitive column.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveTypeId(String sensitiveTypeId) {
            return sensitiveTypeId(Output.of(sensitiveTypeId));
        }

        public DiscoveryJobsResultState build() {
            return $;
        }
    }

}
