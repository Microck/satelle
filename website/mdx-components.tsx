import fumadocsComponents from 'fumadocs-ui/mdx';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Card, Cards } from 'fumadocs-ui/components/card';
import { Callout } from 'fumadocs-ui/components/callout';
import { File, Files, Folder } from 'fumadocs-ui/components/files';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { TypeTable } from 'fumadocs-ui/components/type-table';
import type { MDXComponents } from 'mdx/types';

export function getMDXComponents(components?: MDXComponents): MDXComponents {
  return {
    ...fumadocsComponents,
    Tabs,
    Tab,
    Steps,
    Step,
    Cards,
    Card,
    Callout,
    Files,
    Folder,
    File,
    Accordions,
    Accordion,
    TypeTable,
    ...components,
  };
}

export const useMDXComponents = getMDXComponents;
